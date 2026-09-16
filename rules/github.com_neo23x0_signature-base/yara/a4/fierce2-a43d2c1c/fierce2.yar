rule Fierce2 {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      description = "This signature detects the Fierce2 domain scanner"
      date = "01.07.2014"
      score = 60
      id = "08a72151-48c2-513b-995f-be0d5acba7dd"
   strings:
      $s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
   condition:
      1 of them
}