rule MAL_Malicious_SFX2_Adobe_RID2FAC : DEMO EXE FILE MAL {
   meta:
      description = "SFX with adobe.exe content"
      author = "Florian Roth"
      reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
      date = "2015-07-20 12:07:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "adobe.exe" fullword ascii
      $s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
      $s3 = "GETPASSWORD1" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}