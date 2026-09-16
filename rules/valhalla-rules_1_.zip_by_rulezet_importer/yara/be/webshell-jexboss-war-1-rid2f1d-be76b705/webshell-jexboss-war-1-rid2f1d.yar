rule WebShell_JexBoss_WAR_1_RID2F1D : DEMO FILE T1505_003 WEBSHELL {
   meta:
      description = "Detects JexBoss versions in WAR form"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-11-08 11:43:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "6271775ab144ce9bb9138bf054b149b5813d3beb96338993c6de35330f566092"
      hash2 = "6f14a63c3034d3762da8b3ad4592a8209a0c88beebcb9f9bd11b40e879f74eaf"
      tags = "DEMO, FILE, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $ = "jbossass" fullword ascii
      $ = "jexws.jsp" fullword ascii
      $ = "jexws.jspPK" fullword ascii
      $ = "jexws1.jsp" fullword ascii
      $ = "jexws1.jspPK" fullword ascii
      $ = "jexws2.jsp" fullword ascii
      $ = "jexws2.jspPK" fullword ascii
      $ = "jexws3.jsp" fullword ascii
      $ = "jexws3.jspPK" fullword ascii
      $ = "jexws4.jsp" fullword ascii
      $ = "jexws4.jspPK" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x4b50 and filesize < 4KB and 1 of them
}