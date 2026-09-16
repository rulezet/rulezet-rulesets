rule WEBSHELL_PAS_webshell_SQLDumpFile {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects SQL dump file created by P.A.S. webshell"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 90
      id = "4c26feeb-3031-5c91-9eeb-4b5fe9702e39"
   strings:
      $ = "-- [ SQL Dump created by P.A.S. ] --"
   condition:
      1 of them
}