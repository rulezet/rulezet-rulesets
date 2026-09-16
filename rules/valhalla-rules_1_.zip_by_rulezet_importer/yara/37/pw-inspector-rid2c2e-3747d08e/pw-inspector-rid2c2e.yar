rule pw_inspector_RID2C2E : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file pw-inspector.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:38:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
      $s2 = "http://www.thc.org" fullword ascii
      $s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 460KB and all of them
}