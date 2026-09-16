rule arpsniffer_RID2B41 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file arpsniffer_RID2B41.exe"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:58:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "SHELL" ascii
      $s2 = "PacketSendPacket" fullword ascii
      $s3 = "ArpSniff" ascii
      $s4 = "pcap_loop" fullword ascii
      $s5 = "packet.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 120KB and all of them
}