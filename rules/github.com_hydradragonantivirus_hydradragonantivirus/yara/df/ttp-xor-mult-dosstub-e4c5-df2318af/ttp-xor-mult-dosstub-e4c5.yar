rule TTP_XOR_MULT_DOSStub_e4c5 {
  strings:
    $key_e4c5 = { b0 ad [2] c4 b5 [2] 83 b7 [2] c4 a6 [2] 8a aa [2] 86 a0 [2] 91 ab [2] 8a e5 [2] b7 }

  condition:
    any of them
}