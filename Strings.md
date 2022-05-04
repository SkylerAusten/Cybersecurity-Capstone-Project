# Strings Tool

One of the easiest ways to locate ASCII strings in a binary executable is the **strings** tool.  Simple but powerful, this tool just scans the file you pass it for UNICODE (or ASCII) strings of a **default length of 3** or more UNICODE (or ASCII) characters.  The minumum length can also be increased with the **-n flag**.  A version of the strings tool exists for both *nix and Windows systems.

Strings is an incredibly powerful tool when analyzing executables and object files, but **larger files will make the output of strings difficult to sift through.**  For this reason, strings is most effectively used in combination with other tools such as grep, more, and less.

For example, to search through the strings in a file that contain the text "libc," you might run the following command.
 
```bash strings file.txt | grep libc```

## String Options

### --help
Returns the help page wth detailed descriptions of tool options and use cases.

### -n
Changes the minimum length of string returned by the tool.

### -d
Compiled programs have different areas internally in their data where text is stored.  To have strings search only in initialized, loaded data sections in the file, use the -d (data) option.

### -o
Strings can also print the offset from the start of the file at which each string is located. To do this, use the -o (offset) option.

### -t
By default, the offset returned from -o is represented in Octal.

### -w
By default, strings considers tab and space characters to be apart of strings it finds, 

The -w (whitespace) option causes strings to treat all whitespace characters as though they are parts of the string.

## String Challenge
To learn how strings can be applied in binary file analysis, check out the **~/home/strings/** directory and use the strings tool to locate this challenge's flag.