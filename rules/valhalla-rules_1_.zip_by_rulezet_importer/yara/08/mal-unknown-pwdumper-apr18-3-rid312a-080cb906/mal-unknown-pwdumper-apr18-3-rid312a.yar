rule MAL_Unknown_PWDumper_Apr18_3_RID312A : DEMO EXE FILE HKTL MAL {
   meta:
      description = "Detects sample from unknown sample set - IL origin"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-04-06 13:10:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "d435e7b6f040a186efeadb87dd6d9a14e038921dc8b8658026a90ae94b4c8b05"
      hash2 = "8c35c71838f34f7f7a40bf06e1d2e14d58d9106e6d4e6f6e9af732511a126276"
      tags = "DEMO, EXE, FILE, HKTL, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "loaderx86.dll" fullword ascii
      $s2 = "tcpsvcs.exe" fullword wide
      $s3 = "%Program Files, Common FOLDER%" fullword wide
      $s4 = "%AllUsers, ApplicationData FOLDER%" fullword wide
      $s5 = "loaderx86" fullword ascii
      $s6 = "TNtDllHook$" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}