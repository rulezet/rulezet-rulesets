rule HKTL_MooreR_Port_Scanner {
   meta:
      description = "Auto-generated rule on file MooreR Port Scanner.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "376304acdd0b0251c8b19fea20bb6f5b"
      id = "5d8fb83f-bed3-53d2-bd33-2158911dc7c8"
   strings:
      $s0 = "Description|"
      $s3 = "soft Visual Studio\\VB9yp"
      $s4 = "adj_fptan?4"
      $s7 = "DOWS\\SyMem32\\/o"
   condition:
      all of them
}