# LoadExecutable
 Load an executable to process memory, allowing execution. (such as loading a DLL)


Allows loading of an exe and executing of the entrypoint to run the process within current process, without spawning a child process.

_exit, exit, _cexit, ExitProcess, and TerminateProcess standard and windows library functions will need to be hooked, otherwise "parent" process terminates aswell. 
