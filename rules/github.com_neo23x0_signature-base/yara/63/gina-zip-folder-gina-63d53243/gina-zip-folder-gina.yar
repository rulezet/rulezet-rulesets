rule gina_zip_Folder_gina {
   meta:
      description = "Disclosed hacktool set (old stuff) - file gina.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
      id = "7ebc7218-9c7b-5595-ae7b-f316fc99d1f6"
   strings:
      $s0 = "NEWGINA.dll" fullword ascii
      $s1 = "LOADER ERROR" fullword ascii
      $s3 = "WlxActivateUserShell" fullword ascii
      $s6 = "WlxWkstaLockedSAS" fullword ascii
      $s13 = "WlxIsLockOk" fullword ascii
      $s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
      $s16 = "WlxShutdown" fullword ascii
      $s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
   condition:
      all of them
}