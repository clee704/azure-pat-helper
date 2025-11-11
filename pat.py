#!/bin/env python3
#
# Copyright 2024 Chungmin Lee
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
from datetime import datetime, timedelta
import argparse
import base64
import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import traceback
import urllib.parse
import xml.etree.ElementTree

api_version = '7.1-preview.1'


def run_json_command(cmd_args):
    p = subprocess.run(cmd_args, capture_output=True)
    if p.returncode != 0:
        cmd = ' '.join(cmd_args)
        raise RuntimeError(
            f'Command {cmd!r} returned a non-zero code {p.returncode}\n' +
            f'stdout: {p.stdout.decode(sys.stdout.encoding)}\n' +
            f'stderr: {p.stderr.decode(sys.stdout.encoding)}')
    try:
        return {} if p.stdout == b'' else json.loads(p.stdout)
    except json.decoder.JSONDecodeError as e:
        raise RuntimeError(f'{p.stdout} is not a valid JSON') from e


def az_cmd():
    az_cmd_path = shutil.which('az')
    if az_cmd_path is None:
        raise RuntimeError('az command not found')
    return az_cmd_path


def az_rest(uri, method, query_params=None, body=None, content_type=None,
            response_filter=None):
    params = {'api-version': api_version}
    if query_params is not None:
        params.update(query_params)
    query_string = urllib.parse.urlencode(params)
    uri = f'{uri}?{query_string}'
    cmd_args = [
        az_cmd(), 'rest',
        '--method', method,
        '--uri', uri,
        '--resource', 'https://management.core.windows.net/',
        '--output', 'json']
    if body is not None:
        cmd_args.extend(['--body', body])
    if content_type is not None:
        cmd_args.extend(['--headers', f'Content-Type={content_type}'])
    if response_filter is not None:
        cmd_args.extend(['--query', response_filter])
    if os.environ.get('AZURE_ACCESS_TOKEN'):
        token = os.environ.get('AZURE_ACCESS_TOKEN')
        cmd_args.extend(['--headers', f'Authorization=Bearer {token}'])
    return run_json_command(cmd_args)


# Reference: https://learn.microsoft.com/en-us/rest/api/azure/devops/tokens/pats?view=azure-devops-rest-7.1
def pats_rest(org, method, *args, **kwargs):
    uri = f'https://vssps.dev.azure.com/{org}/_apis/Tokens/Pats'
    return az_rest(uri, method, *args, **kwargs)


def create_pat(org, name, scope, expiration):
    pat = pats_rest(org, 'post', body=f'{{"displayName": "{name}", "scope": '
                    f'"{scope}", "validTo": "{expiration.isoformat()}"}}',
                    content_type='application/json')
    if pat['patTokenError'] != 'none':
        raise RuntimeError(f'PAT creation failed: {pat["patTokenError"]}')
    return pat['patToken']


def list_pats(org):
    return pats_rest(org, 'get', response_filter='patTokens',
                     query_params={'organization': org})


def revoke_pat(org, pat):
    pats_rest(org, 'delete', query_params={
        'authorizationId': pat['authorizationId']})


def format_pat_name(format_string=None, **kwargs):
    if format_string is None:
        format_string = ('{prefix} org={org} host={host} user={user} '
                         'timestamp={timestamp}')
    host = platform.node()
    user = getpass.getuser()
    timestamp = datetime.now()
    return format_string.format(host=host, user=user, timestamp=timestamp,
                                **kwargs)


def get_access_token(resource=None):
    cmd_args = [az_cmd(), 'account', 'get-access-token']
    if resource is not None:
        cmd_args.extend(['--resource', resource])
    return run_json_command(cmd_args)


def get_member_id():
    uri = 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me'
    return az_rest(uri, 'get', response_filter='id')


def get_organizations():
    uri = 'https://app.vssps.visualstudio.com/_apis/accounts'
    member_id = get_member_id()
    return az_rest(uri, 'get', query_params={'memberId': member_id},
                   response_filter='value[].accountName')


class CommandRegistry:
    commands = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        CommandRegistry.commands.append(cls)


class ListCommand(CommandRegistry):
    def run(self, args):
        pats = list_pats(args.organization)
        print(json.dumps(pats, indent=2))

    def register(self, subparsers, parser):
        parser = subparsers.add_parser(
            'list',
            help='list PATs',
            description='List PATs from the given Azure DevOps organization.'
            ' Due to a bug in Azure DevOps REST API, it might return PATs from'
            ' other organizations as well.')
        parser.set_defaults(func=self.run)
        parser.add_argument(
            '-o', '--organization',
            metavar='ORG',
            help='Azure DevOps organization',
            required=True)


class RevokeCommand(CommandRegistry):
    def run(self, args):
        pats = list_pats(args.organization)
        print(f'Found {len(pats)} PAT(s)')
        num_revoked = 0
        for pat in pats:
            name = pat['displayName']
            if args.prefix is None or name.startswith(args.prefix):
                if (args.dry_run or args.yes or
                        input(f'Revoke PAT "{name}"? ') in ('y', 'yes')):
                    if args.dry_run:
                        print(f'Revoked PAT "{name}" (dry run)')
                    else:
                        revoke_pat(args.organization, pat)
                        print(f'Revoked PAT "{name}"')
                    num_revoked += 1
        print(f'Revoked {num_revoked} PAT(s)')

    def register(self, subparsers, parser):
        parser = subparsers.add_parser(
            'revoke',
            help='revoke PATs',
            description='Revoke PATs from the given Azure DevOps organization.'
            ' Due to a bug in Azure DevOps REST API, it might revoke PATs from'
            ' other organizations as well.')
        parser.set_defaults(func=self.run)
        parser.add_argument(
            '-o', '--organization',
            metavar='ORG',
            help='Azure DevOps organization',
            required=True)
        parser.add_argument(
            '--prefix',
            help='revoke PATs whose name starts with this prefix')
        parser.add_argument(
            '-y', '--yes',
            action='store_true',
            help='assume "yes" as answer to all prompts')
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='print PATs that would be revoked, but not actually revoke '
            'them')


class CreateCommand(CommandRegistry):
    def run(self, args):
        name = format_pat_name(args.name, org=args.organization)
        expiration = datetime.now() + timedelta(days=args.expiration_days)
        pat = create_pat(args.organization, name, args.scope, expiration)
        print(json.dumps(pat, indent=2))

    def register(self, subparsers, parser):
        parser = subparsers.add_parser(
            'create',
            help='create PAT',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='Create a PAT in the given Azure DevOps organization.')
        parser.set_defaults(func=self.run)
        parser.add_argument(
            '-o', '--organization',
            metavar='ORG',
            help='Azure DevOps organization',
            required=True)
        parser.add_argument(
            '--name',
            metavar='NAME',
            help='PAT name format',
            default='[PAT] org={org} host={host} user={user} '
            'timestamp={timestamp}')
        parser.add_argument(
            '--scope',
            metavar='SCOPE',
            help='PAT scope (see https://learn.microsoft.com/en-us/azure/'
            'devops/integrate/get-started/authentication/oauth?view=azure-'
            'devops#scopes for more information)',
            default='vso.code')
        parser.add_argument(
            '-e', '--expiration-days',
            metavar='N',
            type=int,
            default=7,
            help='PAT expiration timestamp expressed in the number of days '
            'from now')


class GitCommand(CommandRegistry):
    def run(self, args):
        input_lines = sys.stdin.readlines()
        if not args.use_bearer_token:
            if self.delegate(args, input_lines):
                return
        if args.action == 'get':
            org = self.get_org(input_lines)
            if org:
                token = self.get_token(args, org)
                for line in input_lines:
                    sys.stdout.write(line)
                print(f'username={org}')
                print(f'password={token}')

    def delegate(self, args, input_lines):
        cmd = args.delegate
        if cmd == 'git credential-cache':
            cmd += f' --timeout {args.expiration_days * 86400}'
        cmd += f' {args.action}'
        input_str = ''.join(input_lines).encode(sys.stdin.encoding)
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           input=input_str)
        if p.stdout:
            sys.stdout.write(p.stdout.decode(sys.stdout.encoding))
            return True

    def get_org(self, input_lines):
        host = self.get_value(input_lines, 'host')
        match = re.match(r'^(?P<org>[\w-]+)\.visualstudio\.com$', host)
        if match:
            return match.group('org')
        if host == 'dev.azure.com':
            return self.get_value(input_lines, 'username')

    def get_value(self, input_lines, key):
        lines = [line for line in input_lines if line.startswith(f'{key}=')]
        if len(lines) != 1:
            raise RuntimeError(f'Expected exactly one {key}, but got '
                               f'{len(host_lines)}')
        return lines[0].removeprefix(f'{key}=').removesuffix('\n')

    def get_token(self, args, org):
        if args.use_bearer_token:
            bear = get_access_token(
                resource='499b84ac-1321-427f-aa17-267ca6975798')
            return bear['accessToken']
        else:
            name = format_pat_name(prefix=args.prefix, org=org)
            expiration = datetime.now() + timedelta(days=args.expiration_days)
            pat = create_pat(org, name, 'vso.code_write', expiration)
            return pat['token']

    def register(self, subparsers, parser):
        parser = subparsers.add_parser(
            'git',
            help='Git credential helper',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='Git credential helper implementation. Set '
            f'credential.helper to "/path/to/{parser.prog} git" to use this '
            'as your credential helper.')
        parser.set_defaults(func=self.run)
        parser.add_argument(
            '--delegate',
            metavar='COMMAND',
            help='delegate helper to store credentials',
            default='git credential-cache')
        parser.add_argument(
            '-e', '--expiration-days',
            metavar='N',
            type=int,
            default=7,
            help='PAT expiration timestamp expressed in the number of days '
            'from now')
        parser.add_argument(
            '--prefix',
            help='PAT name prefix',
            default='[Git]')
        parser.add_argument(
            '--use-bearer-token',
            action='store_true',
            help='use bearer token instead of creating a PAT; a generated '
            'bearer token is not reused')
        parser.add_argument(
            'action', choices=['get', 'store', 'erase'])


class RotationCommandBase:
    def run(self, args):
        if args.generate and not args.organizations:
            print("Organizations are required when --generate is used")
            return 1
        orgs = (args.organizations.split(',') if args.organizations else
                self.get_organizations(args))
        if not orgs:
            print('No organizations are specified/found')
            return 1
        if args.revoke:
            self._revoke_pats(orgs, args.prefix)
        expiration = datetime.now() + timedelta(days=args.expiration_days)
        if args.generate:
            self._generate_pats(orgs, args.prefix, expiration, args)
        else:
            self._rotate_pats(orgs, args.prefix, expiration, args)

    def _revoke_pats(self, orgs, prefix):
        for pat in list_pats(orgs[0]):
            regex = re.compile(rf'^{re.escape(prefix)} org=(?P<org>[\w-]+)'
                               r' host=(?P<host>[^=]+) user=')
            match = re.match(regex, pat['displayName'])
            if match:
                org = match.group('org')
                host = match.group('host')
                if org in orgs and host == platform.node():
                    revoke_pat(org, pat)
                    print(f'Revoked PAT {pat["displayName"]!r}')

    def _generate_tokens(self, orgs, prefix, expiration, args):
        tokens = {}
        for org in orgs:
            name = format_pat_name(prefix=prefix, org=org)
            pat = create_pat(org, name, args.scope, expiration)
            tokens[org] = pat['token']
            print(f'Created PAT {pat["displayName"]!r} valid to '
                  f'{pat["validTo"]}')
        return tokens

    def _rotate_pats(self, orgs, prefix, expiration, args):
        tokens = self._generate_tokens(orgs, prefix, expiration, args)
        self.update_tokens(tokens, args)

    def _generate_pats(self, orgs, prefix, expiration, args):
        feeds = args.generate.split(',')
        if len(orgs) == 1:
            orgs = [orgs[0] for feed in feeds]
        tokens = self._generate_tokens(set(orgs), prefix, expiration, args)
        self.generate_file(tokens, orgs, feeds, args)

    def register(self, subparsers, parser):
        parser = subparsers.add_parser(
            self.command_name,
            help=self.command_help,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.set_defaults(func=self.run)
        self.add_arguments(parser)
        parser.add_argument(
            '-o', '--organizations',
            metavar='ORGS',
            help='Azure DevOps organizations separated by commas')
        parser.add_argument(
            '--revoke',
            action=argparse.BooleanOptionalAction,
            help='revoke old PAT tokens generated by this script',
            default=True)
        parser.add_argument(
            '-e', '--expiration-days',
            metavar='N',
            type=int,
            default=7,
            help='PAT expiration timestamp expressed in the number of days '
            'from now')
        parser.add_argument(
            '--prefix',
            help='PAT name prefix',
            default=self.pat_prefix)
        parser.add_argument(
            '--scope',
            metavar='SCOPE',
            help='PAT scope (see https://learn.microsoft.com/en-us/azure/'
            'devops/integrate/get-started/authentication/oauth?view=azure-'
            'devops#scopes for more information)',
            default='vso.packaging_write')
        parser.add_argument('--generate', metavar='FEED', help='comma separated list of feeds to include in the settings file; --org is required for each feed; if all feeds share the same org, a single org can be specified')


class MavenCommand(RotationCommandBase, CommandRegistry):
    command_name = 'maven'
    command_help = 'rotate PAT tokens in Maven settings.xml'
    pat_prefix = '[Maven]'

    maven_namespace = 'http://maven.apache.org/SETTINGS/1.0.0'
    namespaces = {'': maven_namespace}

    template_settings = '''<?xml version='1.0' encoding='utf-8'?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <servers>
    {servers}
  </servers>
</settings>'''

    template_server = '''<server>
  <id>{name}</id>
  <username>{org}</username>
  <password>{pat}</password>
</server>'''

    def get_organizations(self, args):
        xml = self.get_xml(args.settings_path)
        accessible_orgs = get_organizations()
        orgs = set()
        for org in xml.findall('./servers/server/username', self.namespaces):
            if org.text in accessible_orgs:
                orgs.add(org.text)
        return list(orgs)

    def update_tokens(self, tokens, args):
        xml = self.get_xml(args.settings_path)
        for org in tokens:
            token = tokens[org]
            password_xpath = (f'./servers/server[username="{org}"]/password')
            for password in xml.findall(password_xpath, self.namespaces):
                password.text = token
        xml.write(args.settings_path, xml_declaration=True, encoding='utf-8',
                  default_namespace=self.maven_namespace)
        print(f'Updated {args.settings_path}')

    def generate_file(self, tokens, orgs, feeds, args):
        servers = '\n'.join(self.template_server.format(name=feed, org=org, pat=tokens[org]) for org, feed in zip(orgs, feeds))
        settings = self.template_settings.format(servers=servers)
        os.makedirs(os.path.dirname(args.settings_path), exist_ok=True)
        with open(args.settings_path, 'w') as f:
            f.write(settings)
        print(f"Generated {args.settings_path}")

    def get_xml(self, settings_path):
        return xml.etree.ElementTree.parse(settings_path)

    def add_arguments(self, parser):
        parser.add_argument(
            '--settings-path',
            metavar='PATH',
            default=os.path.expanduser('~/.m2/settings.xml'),
            help='path to settings.xml')


class IvyCommand(RotationCommandBase, CommandRegistry):
    command_name = 'ivy'
    command_help = 'rotate PAT tokens in Ivy ivysettings.xml'
    pat_prefix = '[Ivy]'

    def get_organizations(self, args):
        xml = self.get_xml(args.settings_path)
        accessible_orgs = get_organizations()
        orgs = set()
        for cred in xml.findall('./credentials'):
            org = cred.attrib.get("username")
            if org in accessible_orgs:
                orgs.add(org)
        return list(orgs)

    def update_tokens(self, tokens, args):
        xml = self.get_xml(args.settings_path)
        for org in tokens:
            token = tokens[org]
            for cred in xml.findall(f'./credentials[@username="{org}"]'):
                cred.attrib["passwd"]= token
        xml.write(args.settings_path, xml_declaration=True, encoding='utf-8')
        print(f'Updated {args.settings_path}')

    def get_xml(self, settings_path):
        return xml.etree.ElementTree.parse(settings_path)

    def add_arguments(self, parser):
        parser.add_argument(
            '--settings-path',
            metavar='PATH',
            default=os.path.expanduser('~/.ivy2/ivysettings.xml'),
            help='path to ivysettings.xml')


class NpmCommand(RotationCommandBase, CommandRegistry):
    command_name = 'npm'
    command_help = 'rotate PAT tokens in the user npmrc'
    pat_prefix = '[NPM]'

    username_pattern = (r'//(pkgs\.dev\.azure\.com/(?P<org1>[\w-]+)|'
                        r'(?P<org2>[\w-]+)\.pkgs\.visualstudio\.com)/'
                        r'(?P<project>[\w-]+)/_packaging/(?P<feed>[\w-]+)/'
                        r'npm(/registry)?/:username=((?P=org1)|(?P=org2))')
    password_pattern = (r'(?P<key>//(pkgs\.dev\.azure\.com/(?P<org1>[\w-]+)|'
                        r'(?P<org2>[\w-]+)\.pkgs\.visualstudio\.com)/'
                        r'(?P<project>[\w-]+)/_packaging/(?P<feed>[\w-]+)/'
                        r'npm(/registry)?/:_password)='
                        '(?P<token>[A-Za-z0-9+/=]+)')

    def get_organizations(self, args):
        auth_lines = []
        collect_auth_lines = False
        with open(args.npmrc_path) as f:
            for line in f:
                if line.strip() == '; begin auth token':
                    collect_auth_lines = True
                elif collect_auth_lines:
                    if line.strip() == '; end auth token':
                        collect_auth_lines = False
                    else:
                        auth_lines.append(line)
        orgs = set()
        for auth_line in auth_lines:
            org = self.extract_org(auth_line)
            if org:
                orgs.add(org)
        return list(orgs)

    def extract_org(self, auth_line):
        match = re.match(self.username_pattern, auth_line)
        if match:
            return match.group('org1') or match.group('org2')

    def update_tokens(self, tokens, args):
        lines = []
        update_auth_lines = False
        with open(args.npmrc_path) as f:
            for line in f:
                if line.strip() == '; begin auth token':
                    update_auth_lines = True
                elif update_auth_lines:
                    if line.strip() == '; end auth token':
                        update_auth_lines = False
                    else:
                        line = self.update_token(line, tokens)
                lines.append(line)
        with open(args.npmrc_path, 'w') as f:
            f.writelines(lines)

    def update_token(self, line, tokens):
        match = re.match(self.password_pattern, line)
        if match:
            org = match.group('org1') or match.group('org2')
            if org in tokens:
                token = tokens[org]
                token_b64 = base64.b64encode(token.encode()).decode()
                return re.sub(self.password_pattern, rf'\g<key>={token_b64}',
                              line)
        return line

    def add_arguments(self, parser):
        parser.add_argument(
            '--npmrc-path',
            metavar='PATH',
            default=os.path.expanduser('~/.npmrc'),
            help='path to .npmrc')


def main():
    parser = argparse.ArgumentParser(
        description='Azure DevOps PAT helper. Azure CLI is required to run '
        'this script. Before using this script, you must log in to Azure '
        'using `az login`.')
    commands = [cls() for cls in CommandRegistry.commands]
    subparsers = parser.add_subparsers(title='subcommands', required=True)
    for command in commands:
        command.register(subparsers, parser)
    args = parser.parse_args()
    retcode = None
    try:
        retcode = args.func(args)
    except KeyboardInterrupt:
        return 2
    except:
        traceback.print_exc()
        return 1
    return 0 if retcode is None else retcode


if __name__ == '__main__':
    exit(main())
