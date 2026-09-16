rule ProjectM_CrimsonDownloader_RID317E : DEMO EXE FILE G0134 MAL {
   meta:
      description = "Detects ProjectM Malware"
      author = "Florian Roth"
      reference = "http://researchcenter.paloaltonetworks.com/2016/03/unit42-projectm-link-found-between-pakistani-actor-and-operation-transparent-tribe/"
      date = "2016-03-26 13:24:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXE, FILE, G0134, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "E:\\Projects\\m_project\\main\\mj shoaib" 
      $s1 = "\\obj\\x86\\Debug\\secure_scan.pdb" ascii
      $s2 = "secure_scan.exe" fullword wide
      $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|mswall" fullword wide
      $s4 = "secure_scan|mswall" fullword wide
      $s5 = "[Microsoft-Security-Essentials]" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 400KB and $x1 ) or ( all of them )
}