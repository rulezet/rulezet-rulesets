rule HKTL_Fierce2_RID2B23 : DEMO HKTL {
   meta:
      description = "This signature detects the Fierce2 domain scanner"
      author = "Florian Roth"
      reference = "-"
      date = "2014-07-01 08:53:41"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars," 
   condition: 
      1 of them
}