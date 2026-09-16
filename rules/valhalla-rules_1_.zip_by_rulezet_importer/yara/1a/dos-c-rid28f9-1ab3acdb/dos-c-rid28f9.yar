rule Dos_c_RID28F9 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file c.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 19:33:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "!Win32 .EXE." fullword ascii
      $s1 = ".MPRESS1" fullword ascii
      $s2 = ".MPRESS2" fullword ascii
      $s3 = "XOLEHLP.dll" fullword ascii
      $s4 = "</body></html>" fullword ascii
      $s8 = "DtcGetTransactionManagerExA" fullword ascii
      $s9 = "GetUserNameA" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and all of them
}