rule TTP_XOR_MULT_DOSStub_f440 {
  strings:
    $key_f440 = { a0 28 [2] d4 30 [2] 93 32 [2] d4 23 [2] 9a 2f [2] 96 25 [2] 81 2e [2] 9a 60 [2] a7 }

  condition:
    any of them
}