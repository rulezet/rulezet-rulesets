rule ASPack_Chinese {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ASPack Chinese.ini"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "02a9394bc2ec385876c4b4f61d72471ac8251a8e"
      id = "ac821117-7534-5dec-9477-25be87361900"
   strings:
      $s0 = "= Click here if you want to get your registered copy of ASPack" fullword ascii
      $s1 = ";  For beginning of translate - copy english.ini into the yourlanguage.ini" fullword ascii
      $s2 = "E-Mail:                      shinlan@km169.net" fullword ascii
      $s8 = ";  Please, translate text only after simbol '='" fullword ascii
      $s19 = "= Compress with ASPack" fullword ascii
   condition:
      all of them
}