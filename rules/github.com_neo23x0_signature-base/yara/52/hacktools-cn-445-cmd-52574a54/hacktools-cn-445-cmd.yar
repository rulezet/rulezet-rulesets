rule Hacktools_CN_445_cmd {
   meta:
      description = "Disclosed hacktool set - file cmd.bat"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "69b105a3aec3234819868c1a913772c40c6b727a"
      id = "b9693f51-26ac-5bf1-8c4d-ca852a154636"
   strings:
      $bat = "@echo off" fullword ascii
      $s0 = "cs.exe %1" fullword ascii
      $s2 = "nc %1 4444" fullword ascii
   condition:
      uint32(0) == 0x68636540 and $bat at 0 and all of ($s*)
}