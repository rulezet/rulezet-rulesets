rule sig_238_hunt {
   meta:
      description = "Disclosed hacktool set (old stuff) - file hunt.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
      id = "5d9d1f99-2f12-51e9-a554-b349e19d00fb"
   strings:
      $s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
      $s3 = "Usage - hunt \\\\servername" fullword ascii
      $s4 = ".share = %S - %S" fullword wide
      $s5 = "SMB share enumerator and admin finder " fullword ascii
      $s7 = "Hunt only runs on Windows NT..." fullword ascii
      $s8 = "User = %S" fullword ascii
      $s9 = "Admin is %s\\%s" fullword ascii
   condition:
      all of them
}