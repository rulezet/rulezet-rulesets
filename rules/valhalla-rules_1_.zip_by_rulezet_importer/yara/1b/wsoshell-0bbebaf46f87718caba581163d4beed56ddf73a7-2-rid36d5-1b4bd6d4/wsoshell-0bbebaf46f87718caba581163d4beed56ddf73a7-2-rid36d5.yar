rule WSOShell_0bbebaf46f87718caba581163d4beed56ddf73a7_2_RID36D5 : DEMO FILE SCRIPT T1505_003 WEBSHELL {
   meta:
      description = "Detects a web shell"
      author = "Florian Roth"
      reference = "https://github.com/bartblaze/PHP-backdoors"
      date = "2016-09-10 17:12:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d053086907aed21fbb6019bf9e644d2bae61c63563c4c3b948d755db3e78f395"
      tags = "DEMO, FILE, SCRIPT, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s8 = "$default_charset='Wi'.'ndo.'.'ws-12'.'51';" fullword ascii
      $s9 = "$mosimage_session = \"" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x3f3c and filesize < 300KB and all of them )
}