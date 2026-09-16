rule TTP_XOR_MULT_DOSStub_c2c5 {
  strings:
    $key_c2c5 = { 96 ad [2] e2 b5 [2] a5 b7 [2] e2 a6 [2] ac aa [2] a0 a0 [2] b7 ab [2] ac e5 [2] 91 }

  condition:
    any of them
}