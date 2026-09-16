rule Molerats_Jul17_Sample_2_RID2F9C : APT DEMO EXE FILE G0021 {
   meta:
      description = "Detects Molerats sample - July 2017"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07 12:04:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7e122a882d625f4ccac019efb7bf1b1024b9e0919d205105e7e299fb1a20a326"
      tags = "APT, DEMO, EXE, FILE, G0021"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "Folder.exe" fullword ascii
      $s2 = "Notepad++.exe" fullword wide
      $s3 = "RSJLRSJOMSJ" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and all of them )
}