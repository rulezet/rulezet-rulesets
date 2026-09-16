rule MAL_Malicious_SFX1_Voicemail_RID3169 : DEMO FILE MAL {
   meta:
      description = "SFX with voicemail content"
      author = "Florian Roth"
      reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
      date = "2015-07-20 13:21:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "voicemail" ascii
      $s1 = ".exe" ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 1000KB and $s0 in ( 3 .. 80 ) and $s1 in ( 3 .. 80 )
}