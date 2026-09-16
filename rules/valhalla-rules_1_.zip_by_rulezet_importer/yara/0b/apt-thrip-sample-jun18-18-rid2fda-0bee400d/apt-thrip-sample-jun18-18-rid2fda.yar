rule APT_Thrip_Sample_Jun18_18_RID2FDA : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:14:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "33029f5364209e05481cfb2a4172c6dc157b0070f51c05dd34485b8e8da6e820"
      hash2 = "263c01a3b822722dc288a5ac138d953630d8c548a0bee080ae3979b7d364cecb"
      hash3 = "52d190a8d20b4845551b8765cbd12cfbe04cf23e6812e238e5a5023c34ee9b37"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Windows 95/98/Me, Windows NT 4.0, Windows 2000/XP: IME PROCESS key" fullword ascii
      $s2 = "Windows 2000/XP: Either the angle bracket key or the backslash key on the RT 102-key keyboard" fullword ascii
      $s3 = "LoadLibraryA() failed in KbdGetProcAddressByName()" fullword ascii
      $s5 = "Unknown Virtual-Key Code" fullword ascii
      $s6 = "Computer Sleep key" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them
}