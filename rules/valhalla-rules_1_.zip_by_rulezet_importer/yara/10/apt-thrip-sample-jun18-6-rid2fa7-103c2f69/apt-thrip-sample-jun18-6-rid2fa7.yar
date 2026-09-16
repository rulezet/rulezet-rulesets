rule APT_Thrip_Sample_Jun18_6_RID2FA7 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "44f58496578e55623713c4290abb256d03103e78e99939daeec059776bd79ee2"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Windows\\system32\\Instell.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 100KB and 1 of them
}