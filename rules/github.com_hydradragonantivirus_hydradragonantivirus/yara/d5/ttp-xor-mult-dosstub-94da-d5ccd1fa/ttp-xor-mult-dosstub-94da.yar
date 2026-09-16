rule TTP_XOR_MULT_DOSStub_94da {
  strings:
    $key_94da = { c0 b2 [2] b4 aa [2] f3 a8 [2] b4 b9 [2] fa b5 [2] f6 bf [2] e1 b4 [2] fa fa [2] c7 }

  condition:
    any of them
}