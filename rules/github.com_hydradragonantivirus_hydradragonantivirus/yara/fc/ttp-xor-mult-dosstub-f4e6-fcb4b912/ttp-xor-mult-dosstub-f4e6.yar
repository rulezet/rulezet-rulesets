rule TTP_XOR_MULT_DOSStub_f4e6 {
  strings:
    $key_f4e6 = { a0 8e [2] d4 96 [2] 93 94 [2] d4 85 [2] 9a 89 [2] 96 83 [2] 81 88 [2] 9a c6 [2] a7 }

  condition:
    any of them
}