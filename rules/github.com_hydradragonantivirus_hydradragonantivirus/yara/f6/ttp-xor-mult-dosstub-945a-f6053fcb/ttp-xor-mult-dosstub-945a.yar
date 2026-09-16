rule TTP_XOR_MULT_DOSStub_945a {
  strings:
    $key_945a = { c0 32 [2] b4 2a [2] f3 28 [2] b4 39 [2] fa 35 [2] f6 3f [2] e1 34 [2] fa 7a [2] c7 }

  condition:
    any of them
}