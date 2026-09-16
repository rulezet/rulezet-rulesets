rule APT_MAL_Sandworm_Exaramel_Configuration_Key {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects the encryption key for the configuration file used by Exaramel malware as seen in sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "8078de62-3dd2-5ee0-8bda-f508e4013144"
   strings:
      $ = "odhyrfjcnfkdtslt"
   condition:
      all of them
}