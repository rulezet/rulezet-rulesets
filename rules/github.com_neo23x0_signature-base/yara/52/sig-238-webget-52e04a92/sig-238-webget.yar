rule sig_238_webget {
   meta:
      description = "Disclosed hacktool set (old stuff) - file webget.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
      id = "b03a2463-94fe-5050-8e3d-269101a03cda"
   strings:
      $s0 = "Packed by exe32pack" ascii
      $s1 = "GET A HTTP/1.0" fullword ascii
      $s2 = " error " fullword ascii
      $s13 = "Downloa" ascii
   condition:
      all of them
}