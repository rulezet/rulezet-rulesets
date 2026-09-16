rule CN_Tools_MyUPnP_RID2C9A : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file MyUPnP.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:56:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<description>BYTELINKER.COM</description>" fullword ascii
      $s2 = "myupnp.exe" fullword ascii
      $s3 = "LOADER ERROR" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1500KB and all of them
}