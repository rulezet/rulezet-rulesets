rule SUSP_Renamed_Dot1Xtray {
   meta:
      description = "Detects a legitimate renamed dot1ctray.exe, which is often used by PlugX for DLL side-loading"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-11-15"
      hash1 = "f9ebf6aeb3f0fb0c29bd8f3d652476cd1fe8bd9a0c11cb15c43de33bbce0bf68"
      id = "3685a79e-7dd6-5221-b58a-6ec1c61030cc"
   strings:
      $a1 = "\\Symantec_Network_Access_Control\\"  ascii
      $a2 = "\\dot1xtray.pdb" ascii
      $a3 = "DOT1X_NAMED_PIPE_CONNECT" fullword wide 
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
      and not filename matches /dot1xtray.exe/i
      and not filepath matches /Recycle.Bin/i
}