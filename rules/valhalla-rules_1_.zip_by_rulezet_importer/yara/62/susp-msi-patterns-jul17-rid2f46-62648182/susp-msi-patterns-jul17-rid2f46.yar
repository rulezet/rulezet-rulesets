rule SUSP_MSI_Patterns_Jul17_RID2F46 : DEMO FILE HKTL SUSP {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07 11:50:11"
      score = 50
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "a7c498a95850e186b7749a96004a98598f45faac2de9b93354ac93e627508a87"
      tags = "DEMO, FILE, HKTL, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "WShell32.dll" fullword wide
      $s2 = "Target empty, so account name translation begins on the local system." fullword wide
      $s3 = "\\custact\\x86\\AICustAct.pdb" ascii
   condition: 
      ( uint16 ( 0 ) == 0xcfd0 and filesize < 1000KB and all of them )
}