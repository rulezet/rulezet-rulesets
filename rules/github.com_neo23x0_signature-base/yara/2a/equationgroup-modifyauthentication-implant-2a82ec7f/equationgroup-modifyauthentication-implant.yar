rule EquationGroup_modifyAuthentication_Implant {
   meta:
      description = "EquationGroup Malware - file modifyAuthentication_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "e1dff24af5bfc991dca21b4e3a19ffbc069176d674179eef691afc6b1ac6f805"
      id = "990035c5-cd9c-59e0-b244-e2caafd2561f"
   strings:
      $s1 = "LSASS.EXE" fullword wide
      $s2 = "hsamsrv.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
      $s4 = "hOpenProcess" fullword ascii
      $s5 = ".?AVFeFinallyFailure@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}