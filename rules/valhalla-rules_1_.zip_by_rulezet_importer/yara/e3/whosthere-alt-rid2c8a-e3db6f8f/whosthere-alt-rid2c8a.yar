rule whosthere_alt_RID2C8A : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
      date = "2015-07-10 09:53:31"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WHOSTHERE-ALT v1.1 - by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
      $s1 = "whosthere enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii
      $s2 = "dump output to a file, -o filename" fullword ascii
      $s3 = "This tool lists the active LSA logon sessions with NTLM credentials." fullword ascii
      $s4 = "Error: pth.dll is not in the current directory!." fullword ascii
      $s5 = "the output format is: username:domain:lmhash:nthash" fullword ascii
      $s6 = ".\\pth.dll" fullword ascii
      $s7 = "Cannot get LSASS.EXE PID!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 280KB and 2 of them
}