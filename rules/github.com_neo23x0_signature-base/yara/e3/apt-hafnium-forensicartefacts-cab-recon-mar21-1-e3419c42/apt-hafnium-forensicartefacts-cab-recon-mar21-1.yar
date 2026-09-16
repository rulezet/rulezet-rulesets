rule APT_HAFNIUM_ForensicArtefacts_Cab_Recon_Mar21_1 {
   meta:
      description = "Detects suspicious CAB files used by HAFNIUM for recon activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3?u=dstepanic"
      date = "2021-03-11"
      score = 70
      id = "b0caf9d9-af0a-5181-85e4-6091cd6699e3"
   strings:
      $s1 = "ip.txt" ascii fullword
      $s2 = "arp.txt" ascii fullword
      $s3 = "system" ascii fullword 
      $s4 = "security" ascii fullword
   condition:
      uint32(0) == 0x4643534d and
      filesize < 10000KB and (
         $s1 in (0..200) and 
         $s2 in (0..200) and
         $s3 in (0..200) and
         $s4 in (0..200)
      )
}