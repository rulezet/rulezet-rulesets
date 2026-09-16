rule xscan_gui_RID2AD2 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file xscan_gui_RID2AD2.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:41:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
      $s2 = "www.target.com" fullword ascii
      $s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
      $s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}