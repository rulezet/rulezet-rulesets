rule SUSP_ServU_Known_Mal_IP_Jul21_1 {
   meta:
      description = "Detects suspicious IP addresses used in exploitation of ServU services CVE-2021-35211 and reported by Solarwinds"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211#FAQ"
      date = "2021-07-12"
      score = 60
      id = "118272a7-7ec9-568b-99e0-8cfe97f3f64e"
   strings:
      $xip1 = "98.176.196.89" ascii fullword 
      $xip2 = "68.235.178.32" ascii fullword
      $xip3 = "208.113.35.58" ascii fullword
      $xip4 = "144.34.179.162" ascii fullword
      $xip5 = "97.77.97.58" ascii fullword
   condition:
      filename == "DebugSocketlog.txt"
      and 1 of them
}