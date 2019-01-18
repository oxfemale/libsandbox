# libsandbox
A user-space sandbox library via syscall hooking.

This library hooks various NT syscalls to implement a sandbox environment for injected processes. It is designed with limited dependencies and portability in mind.

## Current Features:
- Filesystem Redirection
  - Profiles (e.g. C:\Users\username) will be redirected to a sandbox root path and an anonymized profile (e.g. \path\to\sandbox\DRIVELETTER\Users\PROFILE)
  
  - Application Root (for support of moving around the target application installation) will redirect writes to \path\to\sandbox\[APP_ROOT]
  
  - Absolute path writes (including support for drive letters) redirected to a subdirectory (e.g. D:\Stuff\ = \path\to\sandbox\D\Stuff)
  
  - Reads will prefer sandbox paths over original paths.
  
  - Writes will always write to the sandbox path
  
## Planned Features:
- Subprocess spawn (fork) support to inject sandbox module into spawned child processes.
- Registry sandbox support
- Network sandbox support
- Filesystem search overlay support (viewing the contents of a directory will show a combination of original and sandbox path contents).
