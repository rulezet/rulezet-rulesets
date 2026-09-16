rule APT_Thrip_Sample_Jun18_5_RID2FA6 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:06:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "32889639a27961497d53176765b3addf9fff27f1c8cc41634a365085d6d55920"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "c:\\windows\\USBEvent.exe" fullword ascii
      $s5 = "c:\\windows\\spdir.dat" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}