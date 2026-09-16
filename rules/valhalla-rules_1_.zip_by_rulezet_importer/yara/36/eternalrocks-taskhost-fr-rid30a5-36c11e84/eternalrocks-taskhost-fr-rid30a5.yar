rule EternalRocks_taskhost_FR_RID30A5 : DEMO EXE FILE MAL {
   meta:
      description = "Detects EternalRocks Malware - file taskhost.exe"
      author = "Florian Roth"
      reference = "https://twitter.com/stamparm/status/864865144748298242"
      date = "2017-05-18 12:48:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "EternalRocks.exe" fullword wide
      $s1 = "sTargetIP" fullword ascii
      $s2 = "SERVER_2008R2_SP0" fullword ascii
      $s3 = "20D5CCEE9C91A1E61F72F46FA117B93FB006DB51" fullword ascii
      $s4 = "9EBF75119B8FC7733F77B06378F9E735D34664F6" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and 1 of ( $x* ) or 3 of them )
}