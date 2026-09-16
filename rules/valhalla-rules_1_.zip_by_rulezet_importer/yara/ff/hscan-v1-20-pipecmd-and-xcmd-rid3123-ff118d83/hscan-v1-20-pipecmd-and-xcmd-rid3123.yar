rule HScan_v1_20_PipeCmd_and_xCmd_RID3123 : CHINA DEMO EXE FILE HKTL T1021_002 T1569_002 {
   meta:
      description = "Chinese Hacktool Set - file PipeCmd.exe / xCmd.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 13:09:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1021_002, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
      $s2 = "PipeCmd.exe" fullword wide
      $s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
      $s4 = "%s\\pipe\\%s%s%d" fullword ascii
      $s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
      $s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
      $s7 = "This is a service executable! Couldn't start directly." fullword ascii
      $s8 = "Connecting to Remote Server ...Failed" fullword ascii
      $s9 = "PIPECMDSRV" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 4 of them
}