rule APT_MAL_Sandworm_Exaramel_Strings {
   meta:
      author = "FR/ANSSI/SDO (composed from 4 saparate rules by Florian Roth)"
      description = "Detects Strings used by Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "fdc79b87-eb9e-5751-9474-ff653b073165"
   strings:
      $persistence1 = "systemd"
      $persistence2 = "upstart"
      $persistence3 = "systemV"
      $persistence4 = "freebsd rc"

      $report1 = "systemdupdate.rep"
      $report2 = "upstartupdate.rep"
      $report3 = "remove.rep"

      $url1 = "/tasks.get/"
      $url2 = "/time.get/"
      $url3 = "/time.set"
      $url4 = "/tasks.report"
      $url5 = "/attachment.get/"
      $url6 = "/auth/app"
   condition:
      ( 5 of ($url*) and all of ($persistence*) ) or 
      ( all of ($persistence*) and all of ($report*) ) or 
      ( 5 of ($url*) and all of ($report*) )
}