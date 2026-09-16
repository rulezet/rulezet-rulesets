rule IronGate_PyInstaller_update_EXE_RID3323 : APT DEMO EXE FILE {
   meta:
      description = "Detects a PyInstaller file named update.exe as mentioned in the IronGate APT"
      author = "Florian Roth"
      reference = "https://cloud.google.com/blog/topics/threat-intelligence/irongate-ics-malware/"
      date = "2016-06-04 14:35:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "2044712ceb99972d025716f0f16aa039550e22a63000d2885f7b7cd50f6834e0"
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "bpython27.dll" fullword ascii
      $s5 = "%s%s.exe" fullword ascii
      $s6 = "bupdate.exe.manifest" fullword ascii
      $s9 = "bunicodedata.pyd" fullword ascii
      $s11 = "distutils.sysconfig(" ascii
      $s16 = "distutils.debug(" ascii
      $s18 = "supdate" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and all of them
}