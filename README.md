# Introduction

It's actually a Windows® XP driver that performs SSDT hooking. It replaces some
functions (registry operations in my example code) with some self-defined kernel
code which eventually passes the parameters to the correct system call.

# Windows version

For now I only test it on Windows® XP since it's much easier because XP is
less secure of course.

I didn't test it on later Windows operating systems but I did read some post
saying that the most tricky part to port it to later Windows versions is that
memory holding SSDT is no longer writable with `wp` bit set in `cr0`. But
Windows provides a way to bypass the restriction using **Memory Descriptor
List**(MDL). Modifying `cr0` will compromise your OS and is not recommended.

# Build

If you are skilled at Windows® driver dev, then just ignore this part (and
probably you don't need this toy either).

First download VisualDDK which I use to compile the whole stuff.  Then you can
do whatever you want. Create a project and copy-paste my code or copy the
directory and see if Visual Studio can recognize. If you have any problem, you
can email me.

And there're plenty of tutorials on how to make drivers work with Windows (not
so convenient like Linux though)
