rule pw_inspector_2_RID2CBF : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file pw-inspector.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 10:02:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
      $s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
      $s3 = "PW-Inspector" fullword ascii
      $s4 = "i:o:m:M:c:lunps" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}