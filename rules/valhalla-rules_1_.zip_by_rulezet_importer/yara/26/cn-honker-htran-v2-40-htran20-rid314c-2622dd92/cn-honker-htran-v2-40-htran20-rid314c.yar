rule CN_Honker_Htran_V2_40_htran20_RID314C : CHINA DEMO EXE FILE HKTL T1020 T1090 {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file htran20.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 13:16:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL, T1020, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "%s -slave  ConnectHost ConnectPort TransmitHost TransmitPort" fullword ascii
      $s2 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
      $s3 = "[SERVER]connection to %s:%d error" fullword ascii
      $s4 = "%s -connect ConnectHost [ConnectPort]       Default:%d" fullword ascii
      $s5 = "[+] got, ip:%s, port:%d" fullword ascii
      $s6 = "[-] There is a error...Create a new connection." fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}