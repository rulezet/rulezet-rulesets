rule WinEggDropShellFinal_zip_Folder_InjectT {
   meta:
      description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
      id = "16f04551-050f-5a07-a35b-a3a7dbba6803"
   strings:
      $s0 = "Packed by exe32pack" ascii
      $s1 = "2TInject.Dll" fullword ascii
      $s2 = "Windows Services" fullword ascii
      $s3 = "Findrst6" fullword ascii
      $s4 = "Press Any Key To Continue......" fullword ascii
   condition:
      all of them
}