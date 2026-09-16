rule dll_PacketX_RID2B5C : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 09:03:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s9 = "[Failed to load winpcap packet.dll." wide
      $s10 = "PacketX Version" wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1920KB and all of them
}