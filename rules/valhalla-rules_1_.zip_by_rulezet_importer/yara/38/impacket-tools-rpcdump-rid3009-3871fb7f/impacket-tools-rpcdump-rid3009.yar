rule Impacket_Tools_rpcdump_RID3009 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:22:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "srpcdump" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 17000KB and all of them )
}