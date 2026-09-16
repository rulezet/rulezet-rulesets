rule SUSP_ELF_Tor_Client_RID2DE4 : APT DEMO FILE LINUX SUSP {
   meta:
      description = "Detects ELF Linux Tor client"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24 10:51:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "afd281639e26a717aead65b1886f98d6d6c258736016023b4e59de30b7348719"
      tags = "APT, DEMO, FILE, LINUX, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "We needed to load a secret key from %s, but it was encrypted. Try 'tor --keygen' instead, so you can enter the passphrase." fullword ascii
      $x2 = "Received a VERSION cell with odd payload length %d; closing connection." fullword ascii
      $x3 = "Please upgrade! This version of Tor (%s) is %s, according to the directory authorities. Recommended versions are: %s" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x457f and 1 of them
}