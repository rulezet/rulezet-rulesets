rule WordDoc_PowerShell_URLDownloadToFile_RID34F4 : DEMO FILE MAL OFFICE SCRIPT T1059_001 {
   meta:
      description = "Detects Word Document with PowerShell URLDownloadToFile"
      author = "Florian Roth"
      reference = "https://www.arbornetworks.com/blog/asert/additional-insights-shamoon2/"
      date = "2017-02-23 15:52:31"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "33ee8a57e142e752a9c8960c4f38b5d3ff82bf17ec060e4114f5b15d22aa902e"
      hash2 = "388b26e22f75a723ce69ad820b61dd8b75e260d3c61d74ff21d2073c56ea565d"
      hash3 = "71e584e7e1fb3cf2689f549192fe3a82fd4cd8ee7c42c15d736ebad47b028087"
      tags = "DEMO, FILE, MAL, OFFICE, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $w1 = "Microsoft Forms 2.0 CommandButton" fullword ascii
      $w2 = "Microsoft Word 97-2003 Document" fullword ascii
      $p1 = "powershell.exe" fullword ascii
      $p2 = "URLDownloadToFile" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and 1 of ( $w* ) and all of ( $p* ) )
}