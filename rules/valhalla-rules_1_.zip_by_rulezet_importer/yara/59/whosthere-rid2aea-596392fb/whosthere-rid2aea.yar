rule whosthere_RID2AEA : APT DEMO EXE FILE {
   meta:
      description = "Semiautomatically generated YARA rule - file whosthere_RID2AEA.exe"
      author = "Florian Roth"
      reference = "http://www.coresecurity.com/corelabs-research/open-source-tools/pass-hash-toolkit"
      date = "2015-07-10 09:21:41"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "by Hernan Ochoa (hochoa@coresecurity.com, hernan@gmail.com) - (c) 2007-2008 Core Security Technologies" fullword ascii
      $s2 = "whosthere_RID2AEA enters an infinite loop and searches for new logon sessions every 2 seconds. Only new sessions are shown if found." fullword ascii
      $s3 = "specify addresses to use. Format: ADDCREDENTIAL_ADDR:ENCRYPTMEMORY_ADDR:FEEDBACK_ADDR:DESKEY_ADDR:LOGONSESSIONLIST_ADDR:LOGONSES" ascii
      $s4 = "Could not enable debug privileges. You must run this tool with an account with administrator privileges." fullword ascii
      $s5 = "-B is now used by default. Trying to find correct addresses.." fullword ascii
      $s6 = "Cannot get LSASS.EXE PID!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 320KB and 2 of them
}