rule ByPassFireWall_zip_Folder_Ie {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Ie.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "d1b9058f16399e182c9b78314ad18b975d882131"
      id = "7bd10fa1-be2d-5882-b4c7-b696612343e5"
   strings:
      $s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
      $s1 = "LOADER ERROR" fullword ascii
      $s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
      $s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
   condition:
      all of them
}