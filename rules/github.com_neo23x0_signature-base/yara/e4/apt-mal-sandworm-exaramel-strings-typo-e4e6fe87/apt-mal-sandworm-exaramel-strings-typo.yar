rule APT_MAL_Sandworm_Exaramel_Strings_Typo {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects misc strings in Exaramel malware with typos"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "fdc79b87-eb9e-5751-9474-ff653b073165"
   strings:
      $typo1 = "/sbin/init | awk "
      $typo2 = "Syslog service for monitoring \n"
      $typo3 = "Error.Can't update app! Not enough update archive."
      $typo4 = ":\"metod\""
   condition:
      3 of ($typo*)
}