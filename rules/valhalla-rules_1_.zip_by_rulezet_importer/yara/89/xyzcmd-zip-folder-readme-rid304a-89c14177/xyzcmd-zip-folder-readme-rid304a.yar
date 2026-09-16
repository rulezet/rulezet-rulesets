rule XYZCmd_zip_Folder_Readme_RID304A : DEMO SUSP {
   meta:
      description = "Disclosed hacktool set (old stuff) - file Readme.txt"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-23 12:33:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "3.xyzcmd \\\\RemoteIP /user:Administrator /pwd:1234 /nowait trojan.exe" fullword ascii
      $s20 = "XYZCmd V1.0" fullword ascii
   condition: 
      all of them
}