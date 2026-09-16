rule Impacket_Tools_netview_RID3010 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:23:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.dcerpc.v5.wkst(" ascii
      $s2 = "dummy_threading(" ascii
      $s3 = "snetview" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and all of them )
}