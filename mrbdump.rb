#!/usr/bin/env ruby

class MrbHeader
  attr_accessor :identifier
  attr_accessor :binary_version
  attr_accessor :binary_crc
  attr_accessor :binary_size
  attr_accessor :compiler_name
  attr_accessor :compiler_version
  attr_accessor :insn_ver
  attr_accessor :datasize
  attr_accessor :irep_num
  attr_accessor :start_idx
  attr_accessor :ireps

  def initialize
    @ireps = []
  end
end

class Section
  attr_accessor :identifier
  attr_accessor :section_size
end

class IREP
  attr_accessor :rite_version
  attr_accessor :bytelen
  attr_accessor :iseq
  attr_accessor :pool
  attr_accessor :syms
  attr_accessor :reps        # child IREPs
  attr_accessor :plen
  attr_accessor :rlen        # number of child ireps
  attr_accessor :debug_info

  def initialize
    @iseq = []
    @pool = []
    @syms = []
    @reps = []
    @debug_info = nil
  end

  def iseq_add(str)
    self.iseq << str
  end

  def pool_add(str)
    self.pool << str
  end

  def syms_add(str)
    self.syms << str
  end

  def read bbuf
    i = 0  #XXX

    # irep header
    record_size = bbuf.bin32
    nlocals = bbuf.bin16
    nregs = bbuf.bin16
    self.rlen = bbuf.bin16

    puts "IREP Record Size: #{record_size}"
    puts "Number of Local Variables: #{nlocals}"
    puts "Number of Register Variables: #{nregs}"
    puts "Number of Child IREPs: #{self.rlen}"

    # ISEQ BLOCK
    iseqlen = bbuf.bin32
    printf "  Number of Opcodes: %d\n", iseqlen
    (0...iseqlen).each { |j|
      x = bbuf.bin32
      MDB.disasm(x, i, j)
    }

    # POOL BLOCK
    npools = bbuf.bin32
    puts "  Number of Pool Values: #{npools}"
    (0...npools).each { |i|
      type = bbuf.bin8
      len = bbuf.bin16
      str = bbuf.readstr(len)
      printf "    %03d: %s\n", i, str
    }

    # SYMS BLOCK
    symslen = bbuf.bin32
    printf "  Number of Symbols: %d\n", symslen
    (0...symslen).each { |i|
      len = bbuf.bin16
      if len == 0xffff
        p "len=0xffff"
      end
      name = bbuf.readstr(len)
      printf "    %03d: %s\n", i, name
      nul = bbuf.bin8
    }

    self.rlen.times { |i|
      irep = IREP.new
      irep.read bbuf
      @reps << irep
    }
  end

  def read_debug_info bbuf, filenames
    DebugInfo.new(self).read bbuf, filenames

    self.reps.each { |irep|
      irep.read_debug_info bbuf, filenames
    }
  end
end

class DebugInfo
  def initialize irep
    @irep = irep
  end

  def read bbuf, filenames
    record_size = bbuf.bin32
    puts "  Debug Record Size: #{record_size}"

    flen = bbuf.bin16
    flen.times { |i|
      start_pos = bbuf.bin32
      filename_idx = bbuf.bin16
      puts "    filename: #{filenames[filename_idx]}"

      puts "    lines:"
      line_entry_count = bbuf.bin32
      line_type = bbuf.bin8
      case line_type
      when 0 # mrb_debug_line_ary = 0,
        line_ary = []
        line_entry_count.times { |j|
          lineno = bbuf.bin16
          line_ary << lineno
          puts "      %04u %d" % [j, lineno]
        }
      when 1 # mrb_debug_line_flat_map = 1
        puts "map"
      else
        puts "(XXX: unknown line type)" 
      end
    }

    @irep.debug_info = self
  end
end

class BinaryBuffer
  def initialize(ary)
    @ary = ary
    @pos = 0
  end
  
  attr_reader :pos

  def binn(n)
    if @pos + n > @ary.size
      raise ArgumentError, "try to read #{n} bytes from offset #{@pos} buf we have only #{@ary.size} bytes"
    end
    x = 0
    @ary[@pos, n].bytes.each { |c| x *= 256; x += c }
    @pos += n
    x
  end

  def bin8
    binn(1)
  end

  def bin16
    binn(2)
  end

  def bin32
    binn(4)
  end

  def readstr(n)
    if n == 0
      ""
    else
      x = @ary[@pos, n]
      @pos += n
      x
    end
  end

  def readn(n)
    if @pos + n > @ary.size
      raise ArgumentError, "try to read #{n} bytes from offset #{@pos} buf we have only #{@ary.size} bytes"
    end
    x = @ary[@pos, n].to_i(16)
    @pos += n
    x
  end

  def read8
    readn(2)
  end

  def read16
    readn(4)
  end

  def read32
    readn(8)
  end
end

class MDB
  # Note: you must update the table when src/opcode.h is changed
  # last updated: 5340126443609265d63159e4c391049cb722f828
  @@op = []
  @@op << lambda { |v| "OP_NOP" }
  @@op << lambda { |v| "OP_MOVE\tR%d\tR%d" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_LOADL\tR%d\tL(%d)" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_LOADI\tR%d\t%d" % [ v[:A], v[:sBx] ] }
  @@op << lambda { |v| "OP_LOADSYM\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_LOADNIL\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_LOADSELF\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_LOADT\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_LOADF\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_GETGLOBAL\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_SETGLOBAL\t:%s\tR%d" % [ v[:Bx], v[:A] ] }
  @@op << lambda { |v| "OP_GETSPECIAL\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_SETSPECIAL\t:%s\tR%d" % [ v[:Bx], v[:A] ] }
  @@op << lambda { |v| "OP_GETIV\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_SETIV\t:%s\tR%d" % [ v[:Bx], v[:A] ] }
  @@op << lambda { |v| "OP_GETCV\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_SETCV\t:%s\tR%d" % [ v[:Bx], v[:A] ] }
  @@op << lambda { |v| "OP_GETCONST\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_SETCONST\t:%s\tR%d" % [ v[:Bx], v[:A] ] }
  @@op << lambda { |v| "OP_GETMCNST\tR%d\t:%s" % [ v[:A], v[:Bx] ] }
  @@op << lambda { |v| "OP_SETMCNST\t:%s\tR%d" % [ v[:Bx], v[:A] ] }
  @@op << lambda { |v| "OP_GETUPVAR\tR%d\t%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_SETUPVAR\tR%d\t%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_JMP\t\t%03d" % [ v[:i]+v[:sBx] ] }
  @@op << lambda { |v| "OP_JMPIF\tR%d\t%03d" % [ v[:A], v[:i]+v[:sBx] ] }
  @@op << lambda { |v| "OP_JMPNOT\tR%d\t%03d" % [ v[:A], v[:i]+v[:sBx] ] }
  @@op << lambda { |v| "OP_ONERR\t%03d" % [ v[:i]+v[:sBx] ] }
  @@op << lambda { |v| "OP_RESCUE\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_POPERR\t%s" % v[:A] }
  @@op << lambda { |v| "OP_RAISE\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_EPUSH\t:I(%d)" % [ v[:n]+v[:Bx] ] }
  @@op << lambda { |v| "OP_EPOP\t%s" % v[:A] }
  @@op << lambda { |v| "OP_SEND\tR%d\t:%s\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_SENDB\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_FSEND\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_CALL\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_SUPER\tR%d\t%d" % [ v[:A], v[:C] ] }
  @@op << lambda { |v| "OP_ARGARY\tR%d\t%s" % [ v[:A], v[:Ba] ] }
  @@op << lambda { |v| "OP_ENTER\t%s" % v[:Ax] }
  @@op << lambda { |v| "OP_KARG\tR%d\t%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_KDICT\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_RETURN\tR%d (%d)" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_TAILCALL\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_BLKPUSH\tR%d\t%s" % [ v[:A], v[:Ba] ] }
  @@op << lambda { |v| "OP_ADD\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_ADDI\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_SUB\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_SUBI\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_MUL\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_DIV\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_EQ\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_LT\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_LE\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_GT\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_GE\tR%d\t:%s\t%d" % [ v[:A], v[:Bs], v[:C] ] }
  @@op << lambda { |v| "OP_ARRAY\tR%d\tR%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_ARYCAT\tR%d\tR%d" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_ARYPUSH\tR%d\tR%d" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_AREF\tR%d\tR%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_ASET\tR%d\tR%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_APOST\tR%d\t%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_STRING\tR%d\t%d" % [ v[:A], v[:n]+v[:Bx] ] }
  @@op << lambda { |v| "OP_STRCAT\tR%d\tR%d" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_HASH\tR%d\tR%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_LAMBDA\tR%d\tI(%d)\t%d" % [ v[:A], v[:n]+v[:b], v[:c]]}
  @@op << lambda { |v| "OP_RANGE\tR%d\tR%d\t%d" % [ v[:A], v[:B], v[:C] ] }
  @@op << lambda { |v| "OP_OCLASS\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_CLASS\tR%d\t:%s" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_MODULE\tR%d\t:%s" % [ v[:A], v[:Bs] ] }
  @@op << lambda { |v| "OP_EXEC\tR%d\tI(%d)" % [ v[:A], v[:n]+v[:Bx] ] }
  @@op << lambda { |v| "OP_METHOD\tR%d\t:%s" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_SCLASS\tR%d\tR%d" % [ v[:A], v[:B] ] }
  @@op << lambda { |v| "OP_TCLASS\tR%d" % v[:A] }
  @@op << lambda { |v| "OP_DEBUG" }
  @@op << lambda { |v| "OP_STOP" }
  @@op << lambda { |v| "OP_ERR\tL(%d)" % [ v[:Bx] ] }
  @@op_unknown = lambda { |v| "OP_unknown %d\t%d\t%d\t%d" % [ v[:op], v[:A], v[:B], v[:C]] }

  def getarg_a(x)
    (x >> 23) & 0x1ff
  end

  def getarg_b(x)
    (x >> 14) & 0x1ff
  end

  def disasm(x, n, i)
    c = x & 0x7f
    if c < @@op.size
      insn = @@op[c]
    else
      insn = @@op_unknown
    end

    v = { :op => c, 
          :i => i, 
          :A => (x >> 23) & 0x1ff,
    	  :B => (x >> 14) & 0x1ff,
    	  :C => (x >> 7)  & 0x7f,
    	  :b => (x >> 9)  & 0x3fff,
    	  :c => (x >> 7)  & 0x3,
    	  :n => n,
	  :Ax => format("%d:%d:%d:%d:%d:%d:%d",
                        (x>>25)&0x1f, (x>>20)&0x1f, (x>>19)&0x1, (x>>14)&0x1f,
		        (x>>9)&0x1f, (x>>8)&0x1, (x>>7)&0x1),
	  :Ba => format("%d:%d:%d:%d",
                         (x>>17)&0x3f, (x>>16)&0x1, (x>>11)&0x1f, (x>>7)&0xf),
	  :Bs => (x >> 14) & 0x1ff,	# XXX: lookup symbol
	  :Bx => (x >> 7) & 0xffff,
	  :sBx => ((x >> 7) & 0xffff) - 0x7fff
	  }
    puts "    " + insn.call(v)
  end

  def self.disasm(*args)
    self.new.disasm(*args)
  end
end

filename = ARGV[0]
data = File.open(filename, "rb").read

# load_rite_header()
hdr = MrbHeader.new
bbuf = BinaryBuffer.new(data)

hdr.identifier       = bbuf.readstr(4)
hdr.binary_version   = bbuf.readstr(4)
hdr.binary_crc       = bbuf.bin16
hdr.binary_size      = bbuf.bin32
hdr.compiler_name    = bbuf.readstr(4)
hdr.compiler_version = bbuf.readstr(4)

puts "Rite Binary Identifier: #{hdr.identifier}"
puts "Rite Binary Version: \"#{hdr.binary_version}\""
puts "Rite Binary CRC: 0x#{"%x" % hdr.binary_crc}"
puts "Rite Binary Size: #{hdr.binary_size}"
puts "Rite Compiler Name: \"#{hdr.compiler_name}\""
puts "Rite Compiler Version: \"#{hdr.compiler_version}\""
puts ""

last_irep = nil
nsec = 0
loop do |i|
  nsec += 1
  puts "Section \##{nsec}:"

  sec = Section.new
  sec.identifier = bbuf.readstr(4)
  if sec.identifier == "END\0"
    puts "Section Identifier: END"
    break
  end
  puts "Section Identifier: #{sec.identifier.rstrip}"

  sec.section_size = bbuf.bin32
  puts "Section Size: #{sec.section_size}"

  case sec.identifier
  when "IREP"
    irep = IREP.new
    i = 0  #XXX

    # section header
    irep.rite_version = bbuf.readstr(4)
    puts "IREP Rite Instruction Specification Version: #{irep.rite_version}"

    irep.read bbuf
    last_irep = irep

  when "LINE"
    (last_irep.rlen + 1).times { |i|
      puts "  Lineno Record \##{i}"

      len = bbuf.bin32
      puts "  Lineno Record Length: #{len}"
      fname_len = bbuf.bin16
      fname = bbuf.readstr(fname_len)
      puts "  Lineno Filename: #{fname}"

      niseq = bbuf.bin32
    }
    # irep->rlen + 1
    puts "(skip)"

  when "DBG\0"
    filenames = []

    fname_len = bbuf.bin16
    puts "  Number of Filenames: #{fname_len}"

    fname_len.times { |i|
      len = bbuf.bin16
      name = bbuf.readstr(len)
      puts "    #{name}"
      filenames << name
    }

    last_irep.read_debug_info bbuf, filenames
  else 
    puts "(unknown section)"
  end
  puts
end
