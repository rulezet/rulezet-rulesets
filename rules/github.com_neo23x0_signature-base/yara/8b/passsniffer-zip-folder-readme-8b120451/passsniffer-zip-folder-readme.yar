rule PassSniffer_zip_Folder_readme {
   meta:
      description = "Disclosed hacktool set (old stuff) - file readme.txt"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "a52545ae62ddb0ea52905cbb61d895a51bfe9bcd"
      id = "f5965aa8-0f78-56fd-8e3e-6dc013942cb3"
   strings:
      $s0 = "PassSniffer.exe" fullword ascii
      $s1 = "POP3/FTP Sniffer" fullword ascii
      $s2 = "Password Sniffer V1.0" fullword ascii
   condition:
      1 of them
}