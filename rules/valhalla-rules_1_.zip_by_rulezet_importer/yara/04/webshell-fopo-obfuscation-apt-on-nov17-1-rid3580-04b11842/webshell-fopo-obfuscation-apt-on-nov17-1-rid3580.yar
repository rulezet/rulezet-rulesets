rule Webshell_FOPO_Obfuscation_APT_ON_Nov17_1_RID3580 : APT DEMO FILE NK OBFUS T1505_003 WEBSHELL {
   meta:
      description = "Detects malware from NK APT incident DE"
      author = "Florian Roth"
      reference = "Internal Research - ON"
      date = "2017-11-17 16:15:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-07-31"
      hash1 = "ed6e2e0027d3f564f5ce438984dc8a54577df822ce56ce079c60c99a91d5ffb1"
      tags = "APT, DEMO, FILE, NK, OBFUS, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Obfuscation provided by FOPO" fullword ascii
      $s1 = "\";@eval($" ascii
      $f1 = { 22 29 29 3B 0D 0A 3F 3E } 
   condition: 
      uint16 ( 0 ) == 0x3f3c and filesize < 800KB and ( $x1 or ( $s1 in ( 0 .. 350 ) and $f1 at ( filesize - 23 ) ) )
}