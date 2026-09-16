rule PowerShell_in_Word_Doc {
   meta:
      description = "Detects a powershell and bypass keyword in a Word document"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - ME"
      date = "2017-06-27"
      score = 50
      hash1 = "4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905"
      id = "c9d073ff-25c6-5751-92bf-e22ae7cfd5f5"
   strings:
      $s1 = "POwErSHELl.ExE" fullword ascii nocase
      $s2 = "BYPASS" fullword ascii nocase
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}