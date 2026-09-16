import "pe"
rule APT_Thrip_Sample_Jun18_14_RID2FD6 : APT DEMO EXE FILE G0030 G0076 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21 12:14:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "67dd44a8fbf6de94c4589cf08aa5757b785b26e49e29488e9748189e13d90fb3"
      tags = "APT, DEMO, EXE, FILE, G0030, G0076"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $s1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
      $s2 = "spdirs.dll" fullword ascii
      $s3 = "Provides storm installation services such as Publish, and Remove." fullword ascii
      $s4 = "RegSetValueEx(Svchost\\netsvcs)" fullword ascii
      $s5 = "Load %s Error" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 200KB and ( ( pe.exports ( "InstallA" ) and pe.exports ( "InstallB" ) and pe.exports ( "InstallC" ) ) or all of them )
}