rule TTP_XOR_MULT_DOSStub_94d7 {
  strings:
    $key_94d7 = { c0 bf [2] b4 a7 [2] f3 a5 [2] b4 b4 [2] fa b8 [2] f6 b2 [2] e1 b9 [2] fa f7 [2] c7 }

  condition:
    any of them
}