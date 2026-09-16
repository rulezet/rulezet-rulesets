rule TTP_XOR_MULT_DOSStub_f417 {
  strings:
    $key_f417 = { a0 7f [2] d4 67 [2] 93 65 [2] d4 74 [2] 9a 78 [2] 96 72 [2] 81 79 [2] 9a 37 [2] a7 }

  condition:
    any of them
}