rule APT_MAL_Sandworm_Exaramel_Configuration_Name_Encrypted {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects the specific name of the configuration file in Exaramel malware as seen in sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "1c06f5fc-3435-51cd-92fb-17a4ab6b63ad"
   strings:
      $ = "configtx.json"
   condition:
      all of them
}