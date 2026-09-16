rule EternalRocks_svchost_FR_RID303E : DEMO EXE FILE MAL {
   meta:
      description = "Detects EternalRocks Malware - file taskhost.exe"
      author = "Florian Roth"
      reference = "https://twitter.com/stamparm/status/864865144748298242"
      date = "2017-05-18 12:31:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WczTkaJphruMyBOQmGuNRtSNTLEs" fullword ascii
      $s2 = "svchost.taskhost.exe" fullword ascii
      $s3 = "ConfuserEx v" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 500KB and 2 of them )
}