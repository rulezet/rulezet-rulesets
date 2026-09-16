rule TTP_XOR_MULT_DOSStub_f437 {
  strings:
    $key_f437 = { a0 5f [2] d4 47 [2] 93 45 [2] d4 54 [2] 9a 58 [2] 96 52 [2] 81 59 [2] 9a 17 [2] a7 }

  condition:
    any of them
}