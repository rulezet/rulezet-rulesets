rule webshell_jsp_generic_encoded_shell__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/07"
    score = 40

  strings:
    $sj0 = /\\\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
    $sj1 = /\\\{ ?99, 109, 100\\\}/ wide ascii
    $sj2 = /\\\{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
    $sj3 = /\\\{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
    $sj4 = /\\\{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
    $sj5 = /\\\{ ?101, 120, 101, 99 \\\}/ wide ascii
    $sj6 = /\\\{ ?103, 101, 116, 82, 117, 110/ wide ascii

  condition:
    (filesize >= 300KB and filesize < 900KB
    )
    and any of ($sj*)
}