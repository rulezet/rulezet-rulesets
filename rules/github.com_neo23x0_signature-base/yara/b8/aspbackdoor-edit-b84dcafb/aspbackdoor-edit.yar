rule aspbackdoor_EDIT {
   meta:
      description = "Disclosed hacktool set (old stuff) - file EDIT.ASP"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "12196cf62931cde7b6cb979c07bb5cc6a7535cbb"
      id = "cdcec370-97af-51c0-b81a-35a788f16ef4"
   strings:
      $s1 = "<meta HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html;charset=gb_2312-80\">" fullword ascii
      $s2 = "Set thisfile = fs.GetFile(whichfile)" fullword ascii
      $s3 = "response.write \"<a href='index.asp'>" fullword ascii
      $s5 = "if Request.Cookies(\"password\")=\"juchen\" then " fullword ascii
      $s6 = "Set thisfile = fs.OpenTextFile(whichfile, 1, False)" fullword ascii
      $s7 = "color: rgb(255,0,0); text-decoration: underline }" fullword ascii
      $s13 = "if Request(\"creat\")<>\"yes\" then" fullword ascii
   condition:
      5 of them
}