rule PassSniffer_zip_Folder_readme_RID32AF : DEMO SUSP {
   meta:
      description = "Disclosed hacktool set (old stuff) - file readme.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 14:15:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "PassSniffer.exe" fullword ascii
      $s1 = "POP3/FTP Sniffer" fullword ascii
      $s2 = "Password Sniffer V1.0" fullword ascii
   condition: 
      1 of them
}