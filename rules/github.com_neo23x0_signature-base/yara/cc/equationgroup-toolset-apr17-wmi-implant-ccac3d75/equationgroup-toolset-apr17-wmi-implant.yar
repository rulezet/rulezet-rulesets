rule EquationGroup_Toolset_Apr17_wmi_Implant {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "de08d6c382faaae2b4b41b448b26d82d04a8f25375c712c12013cb0fac3bc704"
      id = "e058d2cc-b963-55bc-9bdd-468f64fe8e6f"
   strings:
      $x1 = "SELECT ProcessId,Description,ExecutablePath FROM Win32_Process" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and all of them )
}