rule ByPassFireWall_zip_Folder_Inject {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Inject.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
      id = "bb31dc53-f3c1-5f8b-84f9-c231a4e1675b"
   strings:
      $s6 = "Fail To Inject" fullword ascii
      $s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
      $s11 = " Successfully" fullword ascii
   condition:
      all of them
}