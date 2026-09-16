rule FVEY_ShadowBroker_README_cup {
   meta:
      description = "Auto-generated rule - file README.cup.NOPEN"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
      date = "2016-12-17"
      hash1 = "98aaad31663b89120eb781b25d6f061037aecaeb20cf5e32c36c68f34807e271"
      id = "876f3d99-cc6d-568a-a202-1b4938436303"
   strings:
      $s3 = "-F file(s)   Full path to target's \"fuser\" program." fullword ascii
      $s4 = "done after the RAT is killed." fullword ascii
   condition:
      1 of them
}