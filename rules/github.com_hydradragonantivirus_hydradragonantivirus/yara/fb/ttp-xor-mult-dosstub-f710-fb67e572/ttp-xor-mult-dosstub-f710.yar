rule TTP_XOR_MULT_DOSStub_f710 {
  strings:
    $key_f710 = { a3 78 [2] d7 60 [2] 90 62 [2] d7 73 [2] 99 7f [2] 95 75 [2] 82 7e [2] 99 30 [2] a4 }

  condition:
    any of them
}