rule Impacket_Tools_sniffer_RID2FFB : DEMO EXE FILE HKTL T1040 {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:20:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
      tags = "DEMO, EXE, FILE, HKTL, T1040"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "ssniffer" fullword ascii
      $s2 = "impacket.dhcp(" ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 15000KB and all of them )
}