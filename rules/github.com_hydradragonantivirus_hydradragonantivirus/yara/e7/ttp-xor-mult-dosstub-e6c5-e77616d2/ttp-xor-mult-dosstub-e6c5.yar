rule TTP_XOR_MULT_DOSStub_e6c5 {
  strings:
    $key_e6c5 = { b2 ad [2] c6 b5 [2] 81 b7 [2] c6 a6 [2] 88 aa [2] 84 a0 [2] 93 ab [2] 88 e5 [2] b5 }

  condition:
    any of them
}