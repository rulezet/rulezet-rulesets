rule MuddyWater_Mal_Doc_Feb18_1_RID306A : DEMO FILE G0069 MAL {
   meta:
      description = "Detects malicious document used by MuddyWater"
      author = "Florian Roth"
      reference = "Internal Research - TI2T"
      date = "2018-02-26 12:38:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3d96811de7419a8c090a671d001a85f2b1875243e5b38e6f927d9877d0ff9b0c"
      tags = "DEMO, FILE, G0069, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "aWV4KFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVuaWNvZGUuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmco" ascii
      $x2 = "U1FCdUFIWUFid0JyQUdVQUxRQkZBSGdBY0FCeUFHVUFjd0J6QUdrQWJ3QnVBQ0FBS" 
   condition: 
      uint16 ( 0 ) == 0xcfd0 and filesize < 3000KB and 1 of them
}