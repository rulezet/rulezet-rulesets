rule TTP_XOR_MULT_DOSStub_93da {
  strings:
    $key_93da = { c7 b2 [2] b3 aa [2] f4 a8 [2] b3 b9 [2] fd b5 [2] f1 bf [2] e6 b4 [2] fd fa [2] c0 }

  condition:
    any of them
}