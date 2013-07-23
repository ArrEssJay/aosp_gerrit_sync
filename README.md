# repo_gerrit_sync

###Python script to push changes from repo (i.e. Android) into gerrit

It is still in early development, takes no options and is hard-coded to connect to servers specified at the top of the script.

It was written to automate mirroring of the Android Source Project in gerrit

*It requests lists of projects from a repo mirror project and a gerrit installation
*Those lists are compared, and any new projects from repo are created it gerrit
*The gerrit git remote is added to any new projects
*Each repo project is pushed to gerrit

##Requirements:
* repo initiated with the --mirror (i.e. bare git projects) option
* gerrit installation accessible via SSH with CLI access

##Todo:
* More intelligent changing of gerrit URL in each repo project
* Ignore list
* Use a config file
* Dependency management
* Tidying
* Better ssh handling
* Handle git description file in gerrit description

