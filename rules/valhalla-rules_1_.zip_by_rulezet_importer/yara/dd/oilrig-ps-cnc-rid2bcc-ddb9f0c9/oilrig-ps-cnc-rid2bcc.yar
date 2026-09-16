rule Oilrig_PS_CnC_RID2BCC : APT DEMO G0049 MIDDLE_EAST SCRIPT T1059_001 {
   meta:
      description = "Powershell CnC using DNS queries"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22 09:21:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9198c29a26f9c55317b4a7a722bf084036e93a41ba4466cbb61ea23d21289cfa"
      tags = "APT, DEMO, G0049, MIDDLE_EAST, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "(-join $base32filedata[$uploadedCompleteSize..$($uploadedCompleteSize" fullword ascii
      $s2 = "$hostname = \"D\" + $fileID + (-join ((65..90) + (48..57) + (97..122)|" ascii
   condition: 
      filesize < 40KB and 1 of them
}