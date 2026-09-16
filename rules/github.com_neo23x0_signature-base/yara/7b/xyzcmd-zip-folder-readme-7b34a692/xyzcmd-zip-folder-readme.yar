rule XYZCmd_zip_Folder_Readme {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Readme.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "967cb87090acd000d22e337b8ce4d9bdb7c17f70"
      id = "cee0f8c3-f947-50a5-ae8c-4ce83ef5e433"
   strings:
      $s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
      $s20 = "XYZCmd V1.0" fullword ascii
   condition:
      all of them
}