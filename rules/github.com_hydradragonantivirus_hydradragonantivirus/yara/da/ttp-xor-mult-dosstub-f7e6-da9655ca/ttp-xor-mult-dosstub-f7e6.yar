rule TTP_XOR_MULT_DOSStub_f7e6 {
  strings:
    $key_f7e6 = { a3 8e [2] d7 96 [2] 90 94 [2] d7 85 [2] 99 89 [2] 95 83 [2] 82 88 [2] 99 c6 [2] a4 }

  condition:
    any of them
}