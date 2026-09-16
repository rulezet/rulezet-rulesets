rule Pirpi_1609_B_RID2AE5 : DEMO EXE FILE G0022 MAL {
   meta:
      description = "Detects Pirpi Backdoor"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 09:13:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "498b98c02e19f4b03dc6a3a8b6ff8761ef2c0fedda846ced4b6f1c87b52468e7"
      tags = "DEMO, EXE, FILE, G0022, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "tconn <ip> <port> //set temp connect value, and disconnect." fullword ascii
      $s2 = "E* ListenCheckSsl SslRecv fd(%d) Error ret:%d %d" fullword ascii
      $s3 = "%s %s L* ListenCheckSsl fd(%d) SslV(-%d-)" fullword ascii
      $s4 = "S:%d.%d-%d.%d V(%d.%d) Listen On %d Ok." fullword ascii
      $s5 = "E* ListenCheckSsl fd(%d) SslAccept Err %d" fullword ascii
      $s6 = "%s-%s N110 Ssl Connect Ok(%s:%d)." fullword ascii
      $s7 = "%s-%s N110 Basic Connect Ok(%s:%d)." fullword ascii
      $s8 = "tconn <ip> <port>" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them ) or ( 4 of them )
}