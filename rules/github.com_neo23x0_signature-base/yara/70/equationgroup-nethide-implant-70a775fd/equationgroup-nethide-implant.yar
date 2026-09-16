rule EquationGroup_nethide_Implant {
   meta:
      description = "EquationGroup Malware - file nethide_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
	  modified = "2023-01-27"
      hash1 = "b2daf9058fdc5e2affd5a409aebb90343ddde4239331d3de8edabeafdb3a48fa"
      id = "36559b69-1718-5d9b-8d6f-3db4becba0c4"
   strings:
      $s1 = "\\\\.\\dlcndi" fullword ascii
      $s2 = "s\\drivers\\" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and all of them )
}