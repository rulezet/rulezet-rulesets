rule PassCV_Sabre_Tool_NTScan_RID3010 : APT DEMO EXE FILE T1021_002 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20 12:23:51"
      score = 90
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0f290612b26349a551a148304a0bd3b0d0651e9563425d7c362f30bd492d8665"
      tags = "APT, DEMO, EXE, FILE, T1021_002"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "NTscan.EXE" fullword wide
      $x2 = "NTscan Microsoft " fullword wide
      $s1 = "admin$" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and 2 of them )
}