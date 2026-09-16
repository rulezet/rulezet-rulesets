rule ArtTray_zip_Folder_ArtTray {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
      id = "d29909a4-8663-54c7-8f0e-68b15def869f"
   strings:
      $s0 = "http://www.brigsoft.com" fullword wide
      $s2 = "ArtTrayHookDll.dll" fullword ascii
      $s3 = "ArtTray Version 1.0 " fullword wide
      $s16 = "TRM_HOOKCALLBACK" fullword ascii
   condition:
      all of them
}