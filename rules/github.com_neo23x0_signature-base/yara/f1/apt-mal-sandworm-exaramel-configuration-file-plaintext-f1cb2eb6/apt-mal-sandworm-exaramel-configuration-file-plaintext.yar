rule APT_MAL_Sandworm_Exaramel_Configuration_File_Plaintext {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects contents of the configuration file used by Exaramel (plaintext)"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "6f0d834b-e6c8-59e6-bf9a-b4fd9c0b2297"
   strings:
      $ = /\{"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":"/
   condition:
      all of them
}