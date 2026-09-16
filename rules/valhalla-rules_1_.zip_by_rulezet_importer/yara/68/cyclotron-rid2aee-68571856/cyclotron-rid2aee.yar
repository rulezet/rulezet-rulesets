rule cyclotron_RID2AEE : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file cyclotron_RID2AEE.sys"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:28:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "\\Device\\IDTProt" wide
      $s2 = "IoDeleteSymbolicLink" fullword ascii
      $s3 = "\\??\\slIDTProt" wide
      $s4 = "IoDeleteDevice" fullword ascii
      $s5 = "IoCreateSymbolicLink" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3KB and all of them
}