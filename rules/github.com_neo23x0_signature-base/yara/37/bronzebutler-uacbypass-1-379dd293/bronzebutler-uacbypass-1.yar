rule BronzeButler_UACBypass_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "fe06b99a0287e2b2d9f7faffbda3a4b328ecc05eab56a3e730cfc99de803b192"
      id = "01853352-58fc-56a3-8c20-08405c71e251"
   strings:
      $x1 = "\\Release\\BypassUacDll.pdb" ascii
      $x2 = "%programfiles%internet exploreriexplore.exe" fullword wide
      $x3 = "Elevation:Administrator!new:{3ad055" fullword wide
      $x4 = "BypassUac.pdb" fullword ascii
      $x5 = "[bypassUAC] started X64" fullword wide
      $x6 = "[bypassUAC] started X86" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them )
}