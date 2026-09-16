rule scanarator_iis {
   meta:
      description = "Auto-generated rule on file iis.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
      id = "a467147b-53c8-53db-aa33-5f0e4e066988"
   strings:
      $s0 = "example: iis 10.10.10.10"
      $s1 = "send error"
   condition:
      all of them
}