rule HKTL_beRootexe_output_RID2F60 : DEMO HKTL {
   meta:
      description = "Detects the output of beRoot.exe"
      author = "Tobias Michalski"
      reference = "https://github.com/AlessandroZ/BeRoot/tree/master/Windows"
      date = "2018-07-25 11:54:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "permissions: {'change_config'" fullword wide
      $s2 = "Full path: C:\\Windows\\system32\\msiexec.exe /V" fullword wide
      $s3 = "Full path: C:\\Windows\\system32\\svchost.exe -k DevicesFlow" fullword wide
      $s4 = "! BANG BANG !" fullword wide
   condition: 
      filesize < 400KB and 3 of them
}