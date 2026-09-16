rule x_way2_5_sqlcmd_RID2CE2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file sqlcmd.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:08:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "LOADER ERROR" fullword ascii
      $s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
      $s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
      $s4 = "kernel32.dll" fullword ascii
      $s5 = "VirtualAlloc" fullword ascii
      $s6 = "VirtualFree" fullword ascii
      $s7 = "VirtualProtect" fullword ascii
      $s8 = "ExitProcess" fullword ascii
      $s9 = "user32.dll" fullword ascii
      $s10 = "MessageBoxA" fullword ascii
      $s12 = "wsprintfA" fullword ascii
      $s13 = "kernel32.dll" fullword ascii
      $s14 = "GetProcAddress" fullword ascii
      $s15 = "GetModuleHandleA" fullword ascii
      $s16 = "LoadLibraryA" fullword ascii
      $s17 = "odbc32.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}