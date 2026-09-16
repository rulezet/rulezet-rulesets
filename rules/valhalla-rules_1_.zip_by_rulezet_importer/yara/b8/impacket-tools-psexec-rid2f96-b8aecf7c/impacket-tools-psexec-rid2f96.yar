rule Impacket_Tools_psexec_RID2F96 : DEMO EXE FILE HKTL T1569_002 {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:03:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
      tags = "DEMO, EXE, FILE, HKTL, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.examples.serviceinstall(" ascii
      $s2 = "spsexec" fullword ascii
      $s3 = "impacket.examples.remcomsvc(" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and 2 of them )
}