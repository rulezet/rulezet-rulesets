rule Impacket_Tools_smbrelayx_RID30E5 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:59:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.examples.secretsdump" fullword ascii
      $s2 = "impacket.examples.serviceinstall" fullword ascii
      $s3 = "impacket.smbserver(" ascii
      $s4 = "SimpleHTTPServer(" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 18000KB and 3 of them )
}