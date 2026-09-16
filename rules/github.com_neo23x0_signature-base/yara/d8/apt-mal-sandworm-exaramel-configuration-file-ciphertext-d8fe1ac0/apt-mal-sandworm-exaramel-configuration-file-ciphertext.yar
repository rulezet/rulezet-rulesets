rule APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext {
   meta:
      author = "FR/ANSSI/SDO"
      description = "Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
      reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
      date = "2021-02-15"
      score = 80
      id = "763dbb17-2bad-5b40-8a7b-b71bc5849cd9"
   strings:
      $ = { 6F B6 08 E9 A3 0C 8D 5E DD BE D4 }    condition:
      all of them
}