rule APT_NK_AR18_165A_1_RID2C15 : APT DEMO EXE FILE NK T1562_001 {
   meta:
      description = "Detects APT malware from AR18-165A report by US CERT"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
      date = "2018-06-15 09:34:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "089e49de61701004a5eff6de65476ed9c7632b6020c2c0f38bb5761bca897359"
      tags = "APT, DEMO, EXE, FILE, NK, T1562_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "netsh.exe advfirewall firewall add rule name=\"PortOpenning\" dir=in protocol=tcp localport=%d action=allow enable=yes" fullword wide
      $s2 = "netsh.exe firewall add portopening TCP %d \"PortOpenning\" enable" fullword wide
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 2000KB and 1 of them
}