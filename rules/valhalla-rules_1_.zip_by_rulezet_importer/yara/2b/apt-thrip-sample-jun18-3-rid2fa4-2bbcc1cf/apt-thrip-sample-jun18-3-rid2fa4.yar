rule APT_Thrip_Sample_Jun18_3_RID2FA4 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:05:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0d2abdcaad99e102fdf6574b3dc90f17cb9d060c20e6ac4ff378875d3b91a840"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Windows\\SysNative\\cmd.exe" fullword ascii
      $s2 = "C:\\Windows\\SysNative\\sysprep\\cryptbase.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them
}