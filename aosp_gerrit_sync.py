#!/usr/bin/python
#Copyright 2013 Robert Jones
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

#Includes code from Parakimo SSH Python library
#Parakimo is licensed under the LGPL. See LICENSE_GPL and LICENSE_LGPL


import os, sys, paramiko, socket, traceback, subprocess
from time import sleep

#Config stuff
#TODO: move to a config file

aosp_branch_local_namespace="aosp"
aosp_tag_local_namespace="aosp"

repo_mirror_base="/media/Android_Build/aosp_upstream_mirror/git"
repo_bin="/usr/local/bin/repo"
gerrit_ssh_host="10.204.66.170"
gerrit_ssh_user="gerrit2"
gerrit_ssh_port=29418
gerrit_ssh_key="/home/gerrit2/.ssh/id_rsa.pub"
gerrit_ssh_key_pw=""
gerrit_git_remote_name="gerrit_aosp"

#if enabled, all gerrit urls in each git will be rewritten
#useful if, say, we're logging in under a new user in gerrit
update_all_urls=False

def main(argv=None):
    if argv is None:
        argv = sys.argv

    #Move to the correct folder for repo to operate in
    os.chdir(repo_mirror_base)

    #Open SSH Transport
    t = open_ssh_session()

    #get gerrit project list
    gp = gerrit_get_projects(t)

    print "gerrit projects:"
    #for project in gp:
    #    print "### " + project

    rp = repo_projects()
    
    #prepend projects with local namespace
    #for index, project in enumerate(rp):
    #    rp[index]=(aosp_branch_local_namespace+"/"+project[0],project[1])

    #get list of project names (prepended with namespace) from repo tuples
    rpn = [aosp_branch_local_namespace+"/"+project[0] for project in rp]
    #rpn = zip(*rp)

    #print "repo projects:"
    #for project in rpn:
    #    print "### " + project

    #check for duplicates - die if this is true
    if len(rpn) != len(set(rpn)):
        print "Duplicate projects from repo!"
        return 1

    #find projects not in gerrit
    np = list(set(rpn) - set(gp))
    print "****Found "+str(len(np))+" new projects"

    #add new projects to gerrit
    for project in np:
        print "Adding new project to gerrit: "+project
        gerrit_create_project(t, project)

    #does each git have gerrit remote?
    if update_all_urls:
        url_update_list = rp
    else:
        url_update_list = np
        print "Checking All Projects for gerrit remote"
        for project in url_update_list:
            #use repo forall with project name filter for relevant project
            r = repo_forall(project[0], 'git', ['remote'])
            remotes = r.splitlines()
            if gerrit_git_remote_name in remotes:
                print "Removing old gerrit remote for " +project[0]
                r = repo_forall(project[0], 'git', ['remote','rm',gerrit_git_remote_name])

            #TODO - only replace the remote if it isn't correct configured
            print "Adding remote for " + project[0]
            repo_url = ("ssh://"
                        +gerrit_ssh_user
                        +"@"
                        +gerrit_ssh_host
                        +":"
                        +str(gerrit_ssh_port)
                        +"/"
                        +aosp_branch_local_namespace
                        +"/"
                        +project[0])
            print "new URL: " + repo_url
            r = repo_forall(project[0], 'git', ['remote', 'add', gerrit_git_remote_name, repo_url])

    #push repo to gerrit
    #set the namespace'd branch mapping
    #branchmap = 'refs/*:refs/' + aosp_branch_local_namespace + "/*"
    #branchmap = ''
    for project in rp:
        print "Pushing repo to gerrit for: " + project[0]
        #print "branch mapping: " + branchmap
        #r = repo_forall(project[0], 'git', ['push', gerrit_git_remote_name, branchmap])
        r = repo_forall(project[0], 'git', ['push', '--all', gerrit_git_remote_name])
        print r

    t.close()
    return 0

def repo_projects():
    args = ['list']
    s = repo(args)
    items = str(s).splitlines()
    projects = []
    for line in items:
        spl = line.split(' : ')
        if spl[0]=="None":
            print "!!!Skipping project :"+spl[0]+" "+spl[1]
        else:
            projects.append((spl[0],spl[1]))
    return projects

def repo_forall(project, command, args):
    args[:0] = ['forall',project,'-c',command]
    r = repo(args)
    return r

def repo(args):
    args[:0] = [repo_bin]
    stderr=""
    r = subprocess.check_output(args)
    return r

def gerrit_create_project(transport, project):
    command = "create-project"
    description = "Imported by aosp_gerrit_sync.py"
    args = [project,'--description',"\"\'"+description+"\'\""]
    #TODO - import git description file
    result = gerrit_execute_cmd(transport, command, args)
    #print "dummy create: " + str(args)

def gerrit_get_projects(transport):
    command = "ls-projects"
    args = []
    project_list = gerrit_execute_cmd(transport, command, args)
    projects = str(project_list).splitlines()
    return projects

def gerrit_execute_cmd(transport, command, args):
    #create the command string
    args[:0]= ['gerrit',command]
    r = execute_ssh_cmd(transport," ".join(args))
    return r

##SSH Stuff below here mostly copied from paramiko demo app

def open_ssh_session():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((gerrit_ssh_host, gerrit_ssh_port))
    except Exception, e:
        print '*** Connect failed: ' + str(e)
        traceback.print_exc()
        sys.exit(1)

    try:
        t = paramiko.Transport(sock)
        try:
            t.start_client()
        except paramiko.SSHException:
            print '*** SSH negotiation failed.'
            sys.exit(1)

        try:
            keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        except IOError:
            try:
                keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
            except IOError:
                print '*** Unable to open host keys file'
                keys = {}

        # check server's host key -- this is important.
        key = t.get_remote_server_key()
        if not keys.has_key(gerrit_ssh_host):
            print '*** WARNING: Unknown host key!'
        elif not keys[gerrit_ssh_host].has_key(key.get_name()):
            print '*** WARNING: Unknown host key!'
        elif keys[gerrit_ssh_host][key.get_name()] != key:
            print '*** WARNING: Host key has changed!!!'
            sys.exit(1)
        else:
            print '*** Host key OK.'

        agent_auth(t, gerrit_ssh_user)
        if not t.is_authenticated():
            manual_auth(t, gerrit_ssh_user, gerrit_ssh_host)
        if not t.is_authenticated():
            print '*** Authentication failed. :('
            t.close()
            sys.exit(1)

        return t

    except Exception, e:
        generic_exception_trace(e,t)

def execute_ssh_cmd(transport,cmd):
    try:
        print "open channel"
        chan = transport.open_session()
        chan.set_combine_stderr(True)
        print "-->Executing SSH Command: "+str(cmd)
        chan.exec_command(cmd)

        #while chan.recv_ready() == False:
        #    sleep(0.05)
        #    print "Waiting for data..."
        r = chan.recv(100000)
        #print "return " + r
        print "close channel"
        chan.close()
        return r

    except Exception, e:
        generic_exception_trace(e,transport)

def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """
    
    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return
        
    for key in agent_keys:
        print 'Trying ssh-agent key %s' % hexlify(key.get_fingerprint()),
        try:
            transport.auth_publickey(username, key)
            print '... success!'
            return
        except paramiko.SSHException:
            print '... nope.'

def manual_auth(transport, username, hostname):
    default_auth = 'r'
    auth='r'
    #auth = raw_input('Auth by (p)assword, (r)sa key, or (d)ss key? [%s] ' % default_auth)
    #if len(auth) == 0:
    #    auth = default_auth

    if auth == 'r':
        default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_rsa')
        #path = raw_input('RSA key [%s]: ' % default_path)
        path = default_path
        #if len(path) == 0:
        #    path = default_path
        try:
            key = paramiko.RSAKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            #password = getpass.getpass('RSA key password: ')
            password = gerrit_ssh_key_pw
            ##INSECURE!!!!
            key = paramiko.RSAKey.from_private_key_file(path, password)
        transport.auth_publickey(username, key)
    elif auth == 'd':
        default_path = os.path.join(os.environ['HOME'], '.ssh', 'id_dsa')
        path = raw_input('DSS key [%s]: ' % default_path)
        if len(path) == 0:
            path = default_path
        try:
            key = paramiko.DSSKey.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            password = getpass.getpass('DSS key password: ')
            key = paramiko.DSSKey.from_private_key_file(path, password)
        transport.auth_publickey(username, key)
    else:
        pw = getpass.getpass('Password for %s@%s: ' % (username, hostname))
        transport.auth_password(username, pw)

def generic_exception_trace(e,transport):
    print '*** Caught exception: ' + str(e.__class__) + ': ' + str(e)
    traceback.print_exc()
    try:
        transport.close()
    except:
        pass
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())

