rule Codoso_PGV_PVID_1_RID2CE6 : DEMO EXE G0073 MAL {
   meta:
      description = "Detects Codoso APT PGV PVID Malware"
      author = "Florian Roth"
      reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
      date = "2016-01-30 10:08:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "41a936b0d1fd90dffb2f6d0bcaf4ad0536f93ca7591f7b75b0cd1af8804d0824"
      hash2 = "58334eb7fed37e3104d8235d918aa5b7856f33ea52a74cf90a5ef5542a404ac3"
      hash3 = "934b87ddceabb2063b5e5bc4f964628fe0c63b63bb2346b105ece19915384fc7"
      tags = "DEMO, EXE, G0073, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Cookie: pgv_pvid=" ascii
      $x2 = "DRIVERS\\ipinip.sys" fullword wide
      $s1 = "TsWorkSpaces.dll" fullword ascii
      $s2 = "%SystemRoot%\\System32\\wiaservc.dll" fullword wide
      $s3 = "/selfservice/microsites/search.php?%016I64d" fullword ascii
      $s4 = "/solutions/company-size/smb/index.htm?%016I64d" fullword ascii
      $s5 = "Microsoft Chart ActiveX Control" fullword wide
      $s6 = "MSChartCtrl.ocx" fullword wide
      $s7 = "{%08X-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}" fullword ascii
      $s8 = "WUServiceMain" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and ( 1 of ( $x* ) or 3 of them ) ) or 5 of them
}