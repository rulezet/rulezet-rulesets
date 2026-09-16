rule splitjoin {
   meta:
      description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
      id = "2f1a69cd-34b3-5af0-a054-fe19d9becb25"
   strings:
      $s0 = "Not for distribution without the authors permission" fullword wide
      $s2 = "Utility to split and rejoin files.0" fullword wide
      $s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
      $s19 = "SplitJoin" fullword wide
   condition:
      all of them
}