rule Hacktools_CN_Http {
   meta:
      description = "Disclosed hacktool set - file Http.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "17.11.14"
      score = 60
      hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
      id = "bbff6ff6-8cef-5a83-afd3-34f306e8e715"
   strings:
      $s0 = "RPCRT4.DLL" fullword ascii
      $s1 = "WNetAddConnection2A" fullword ascii
      $s2 = "NdrPointerBufferSize" fullword ascii
      $s3 = "_controlfp" fullword ascii
   condition:
      all of them and filesize < 10KB
}