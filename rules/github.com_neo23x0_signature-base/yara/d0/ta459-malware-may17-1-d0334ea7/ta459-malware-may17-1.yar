rule TA459_Malware_May17_1 {
   meta:
      description = "Detects TA459 related malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/RLf9qU"
      date = "2017-05-31"
      hash1 = "5fd61793d498a395861fa263e4438183a3c4e6f1e4f098ac6e97c9d0911327bf"
      id = "eb5d2464-ab95-5f5d-8b20-fa023da53130"
   strings:
      $s3 = "xtsewy" fullword ascii
      $s6 = "CW&mhAklnfVULL" ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 800KB and all of them )
}