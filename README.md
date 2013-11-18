mrbdump
=======

mrbdump is a tool to display information about mrb files.


## Requirement
You need Ruby or mruby interpreter to run mrbdump.


## Example

```
% cat a.rb
p "Hello"

% mrbc a.rb

% mrbdump.rb a.mrb
Rite Binary Identifier: RITE
Rite Binary Version: "0002"
Rite Binary CRC: 0x493c
Rite Binary Size: 92
Rite Compiler Name: "MATZ"
Rite Compiler Version: "0000"

Section #1:
Section Identifier: IREP
Section Size: 62
IREP Rite Instruction Specification Version: 0000
IREP Record Size: 50
Number of Local Variables: 1
Number of Register Variables: 3
Number of Child IREPs: 0
  Number of Opcodes: 4
    OP_LOADSELF R1
    OP_STRING   R2      0
    OP_SEND     R1      :0      1
    OP_STOP
  Number of Pool Values: 1
    000: Hello
  Number of Symbols: 1
    000: p

Section #2:
Section Identifier: END
```


## License
Copyright (c) 2012 Internet Initiative Japan Inc.

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in 
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
DEALINGS IN THE SOFTWARE.
