rule TTP_XOR_MULT_DOSStub_b6c5 {
  strings:
    $key_b6c5 = { e2 ad [2] 96 b5 [2] d1 b7 [2] 96 a6 [2] d8 aa [2] d4 a0 [2] c3 ab [2] d8 e5 [2] e5 }

  condition:
    any of them
}