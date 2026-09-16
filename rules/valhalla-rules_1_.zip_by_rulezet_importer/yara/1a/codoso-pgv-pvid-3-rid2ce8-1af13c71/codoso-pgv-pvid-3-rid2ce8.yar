rule Codoso_PGV_PVID_3_RID2CE8 : DEMO G0073 MAL {
   meta:
      description = "Detects Codoso APT PGV PVID Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:09:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "126fbdcfed1dfb31865d4b18db2fb963f49df838bf66922fea0c37e06666aee1"
      hash2 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
      hash3 = "8a56b476d792983aea0199ee3226f0d04792b70a1c1f05f399cb6e4ce8a38761"
      tags = "DEMO, G0073, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Copyright (C) Microsoft Corporation.  All rights reserved.(C) 2012" fullword wide
   condition: 
      $x1
}