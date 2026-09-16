rule HKTL_Ncrack_RID2AF5 : DEMO HKTL T1110 {
   meta:
      description = "This signature detects the Ncrack brute force tool"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 09:40:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1110"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via" 
   condition: 
      1 of them
}