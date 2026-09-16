rule SUSP_Powershell_ShellCommand_May18_1 {
   meta:
      description = "Detects a supcicious powershell commandline"
      author = "Tobias Michalski"
      reference = "https://github.com/0x00-0x00/ShellPop"
      date = "2018-05-18"
      hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
      id = "efa81fd0-b764-5a1a-98a5-fc3135be220b"
   strings:
      $x1 = "powershell -nop -ep bypass -Command" ascii
   condition:
      filesize < 3KB and 1 of them

}