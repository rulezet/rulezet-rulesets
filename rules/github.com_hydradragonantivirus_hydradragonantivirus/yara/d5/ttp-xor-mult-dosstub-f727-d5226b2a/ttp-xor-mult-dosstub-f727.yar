rule TTP_XOR_MULT_DOSStub_f727 {
  strings:
    $key_f727 = { a3 4f [2] d7 57 [2] 90 55 [2] d7 44 [2] 99 48 [2] 95 42 [2] 82 49 [2] 99 07 [2] a4 }

  condition:
    any of them
}