rule APT_Thrip_Sample_Jun18_2_RID2FA3 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:05:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "1fc9f7065856cd8dc99b6f46cf0953adf90e2c42a3b65374bf7b50274fb200cc"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" fullword ascii
      $s2 = "ProbeScriptFint" fullword wide
      $s3 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 60KB and all of them
}