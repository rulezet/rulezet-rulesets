rule Molerats_Jul17_Sample_4_RID2F9E : APT DEMO G0021 {
   meta:
      description = "Detects Molerats sample - July 2017"
      author = "Florian Roth"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07 12:04:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "512a14130a7a8b5c2548aa488055051ab7e725106ddf2c705f6eb4cfa5dc795c"
      tags = "APT, DEMO, G0021"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "get-itemproperty -path 'HKCU:\\SOFTWARE\\Microsoft\\' -name 'KeyName')" wide
      $x2 = "O.Run C & chrw(34) & \"[System.IO.File]::" wide
      $x3 = "HKCU\\SOFTWARE\\Microsoft\\\\KeyName\"" fullword wide
   condition: 
      ( filesize < 700KB and 1 of them )
}