rule QQ_zip_Folder_QQ {
   meta:
      description = "Disclosed hacktool set (old stuff) - file QQ.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
      id = "30da6292-f670-5b73-985a-3028e20607be"
   strings:
      $s0 = "EMAIL:haoq@neusoft.com" fullword wide
      $s1 = "EMAIL:haoq@neusoft.com" fullword wide
      $s4 = "QQ2000b.exe" fullword wide
      $s5 = "haoq@neusoft.com" fullword ascii
      $s9 = "QQ2000b.exe" fullword ascii
      $s10 = "\\qq2000b.exe" ascii
      $s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
      $s17 = "SOFTWARE\\HAOQIANG\\" ascii
   condition:
      5 of them
}