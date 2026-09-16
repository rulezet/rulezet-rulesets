rule TTP_XOR_MULT_DOSStub_f420 {
  strings:
    $key_f420 = { a0 48 [2] d4 50 [2] 93 52 [2] d4 43 [2] 9a 4f [2] 96 45 [2] 81 4e [2] 9a 00 [2] a7 }

  condition:
    any of them
}