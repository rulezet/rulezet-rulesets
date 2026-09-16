rule TTP_XOR_MULT_DOSStub_e657 {
  strings:
    $key_e657 = { b2 3f [2] c6 27 [2] 81 25 [2] c6 34 [2] 88 38 [2] 84 32 [2] 93 39 [2] 88 77 [2] b5 }

  condition:
    any of them
}