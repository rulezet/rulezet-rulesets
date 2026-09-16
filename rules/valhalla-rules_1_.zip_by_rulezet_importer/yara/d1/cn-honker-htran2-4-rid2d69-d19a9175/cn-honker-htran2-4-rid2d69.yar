rule CN_Honker_HTran2_4_RID2D69 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Sample from CN Honker Pentest Toolset - file HTran2.4.exe"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:30:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
      $s2 = "[+] New connection %s:%d !!" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 180KB and all of them
}