rule TTP_XOR_MULT_DOSStub_f7f0 {
  strings:
    $key_f7f0 = { a3 98 [2] d7 80 [2] 90 82 [2] d7 93 [2] 99 9f [2] 95 95 [2] 82 9e [2] 99 d0 [2] a4 }

  condition:
    any of them
}