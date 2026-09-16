rule aspfile2 {
   meta:
      description = "Disclosed hacktool set (old stuff) - file aspfile2.asp"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "14efbc6cb01b809ad75a535d32b9da4df517ff29"
      id = "42bbcc16-a6d7-53d7-8651-1a28c6b26ee8"
   strings:
      $s0 = "response.write \"command completed success!\" " fullword ascii
      $s1 = "for each co in foditems " fullword ascii
      $s3 = "<input type=text name=text6 value=\"<%= szCMD6 %>\"><br> " fullword ascii
      $s19 = "<title>Hello! Welcome </title>" fullword ascii
   condition:
      all of them
}