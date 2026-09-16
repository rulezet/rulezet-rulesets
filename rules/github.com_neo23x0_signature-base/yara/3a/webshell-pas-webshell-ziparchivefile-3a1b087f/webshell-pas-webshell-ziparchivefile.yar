rule WEBSHELL_PAS_webshell_ZIPArchiveFile {
   meta:
      author = "FR/ANSSI/SDO (modified by Florian Roth)"
      description = "Detects an archive file created by P.A.S. for download operation"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "081cc65b-e51c-59fc-a518-cd986e8ee2f7"
   strings:
      $s1 = "Archive created by P.A.S. v."
   condition:
      $s1
}