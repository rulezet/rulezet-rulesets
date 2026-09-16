rule URL_File_Local_EXE_RID2D6E : DEMO SCRIPT T1059 {
   meta:
      description = "Detects an .url file that points to a local executable"
      author = "Florian Roth"
      reference = "https://twitter.com/malwareforme/status/915300883012870144"
      date = "2017-10-04 10:31:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, T1059"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[InternetShortcut]" ascii wide fullword
      $s2 = /URL=file:\/\/\/C:\\[^\n]{1,50}\.exe/ 
   condition: 
      filesize < 400 and all of them
}