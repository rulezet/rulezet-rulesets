rule TTP_XOR_MULT_DOSStub_f4d0 {
  strings:
    $key_f4d0 = { a0 b8 [2] d4 a0 [2] 93 a2 [2] d4 b3 [2] 9a bf [2] 96 b5 [2] 81 be [2] 9a f0 [2] a7 }

  condition:
    any of them
}