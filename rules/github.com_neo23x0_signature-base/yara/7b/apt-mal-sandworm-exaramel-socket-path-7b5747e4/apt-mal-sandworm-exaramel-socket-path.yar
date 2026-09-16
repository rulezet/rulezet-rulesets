rule APT_MAL_Sandworm_Exaramel_Socket_Path {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects path of the unix socket created to prevent concurrent executions in Exaramel malware"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "3aab84c9-9748-5d11-9cd7-efa9151036cf"
   strings:
      $ = "/tmp/.applocktx"
   condition:
      all of them
}