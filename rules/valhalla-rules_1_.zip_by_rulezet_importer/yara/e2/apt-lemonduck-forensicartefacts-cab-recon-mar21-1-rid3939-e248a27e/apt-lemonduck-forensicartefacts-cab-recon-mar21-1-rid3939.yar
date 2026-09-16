rule APT_LemonDuck_ForensicArtefacts_Cab_Recon_Mar21_1_RID3939 : APT DEMO FILE {
   meta:
      description = "Detects suspicious CAB files used by LemonDuck for recon activity"
      author = "Florian Roth"
      reference = "https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3?u=dstepanic"
      date = "2021-03-11 18:54:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ip.txt" ascii fullword
      $s2 = "arp.txt" ascii fullword
      $s3 = "system" ascii fullword
      $s4 = "security" ascii fullword
   condition: 
      uint32 ( 0 ) == 0x4643534d and filesize < 10000KB and ( $s1 in ( 0 .. 200 ) and $s2 in ( 0 .. 200 ) and $s3 in ( 0 .. 200 ) and $s4 in ( 0 .. 200 ) )
}