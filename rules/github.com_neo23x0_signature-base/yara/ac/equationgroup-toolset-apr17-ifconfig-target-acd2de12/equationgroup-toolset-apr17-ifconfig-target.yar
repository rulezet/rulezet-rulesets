rule EquationGroup_Toolset_Apr17_Ifconfig_Target {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "1ebfc0ce7139db43ddacf4a9af2cb83a407d3d1221931d359ee40588cfd0d02b"
      id = "db8ec377-a9f6-5d75-a123-aa0365d98065"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%hs" fullword wide

      $op1 = { 0f be 37 85 f6 0f 85 4e ff ff ff 45 85 ed 74 21 }
      $op2 = { 4c 8d 44 24 34 48 8d 57 08 41 8d 49 07 e8 a6 4b }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}