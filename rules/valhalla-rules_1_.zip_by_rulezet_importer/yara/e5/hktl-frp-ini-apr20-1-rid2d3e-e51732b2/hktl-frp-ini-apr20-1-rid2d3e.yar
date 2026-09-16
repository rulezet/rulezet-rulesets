rule HKTL_FRP_INI_Apr20_1_RID2D3E : DEMO FILE HKTL T1090 {
   meta:
      description = "Detects FRP fast reverse proxy tool INI file often used by threat groups"
      author = "Florian Roth"
      reference = "Chinese Hacktools OpenDir"
      date = "2020-04-07 10:23:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1dabef3c170e4e559c50d603d47fb7f66f6e3da75a65c3435b18175d6e9785bb"
      tags = "DEMO, FILE, HKTL, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $h1 = "[common]" ascii
      $s1 = "server_addr =" ascii fullword
      $s2 = "remote_port =" ascii fullword
      $s3 = "[RemoteDesktop]" ascii fullword
      $s4 = "local_ip = " ascii
      $s5 = "type = tcp" ascii fullword
   condition: 
      uint16 ( 0 ) == 0x635b and filesize < 1KB and $h1 at 0 and all of them
}