rule HKTL_beRootexe_output {
   meta:
      description = "Detects the output of beRoot.exe"
      author = "Tobias Michalski"
      reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
      date = "2018-07-25"
      id = "dfd11915-443f-5ce9-b94a-bdcb0e62104e"
   strings:
      $s1 = "permissions: {'change_config'" fullword wide
      $s2 = "Full path: C:\\Windows\\system32\\msiexec.exe /V" fullword wide
      $s3 = "Full path: C:\\Windows\\system32\\svchost.exe -k DevicesFlow" fullword wide
      $s4 = "! BANG BANG !" fullword wide
   condition:
      filesize < 400KB and 3 of them
}