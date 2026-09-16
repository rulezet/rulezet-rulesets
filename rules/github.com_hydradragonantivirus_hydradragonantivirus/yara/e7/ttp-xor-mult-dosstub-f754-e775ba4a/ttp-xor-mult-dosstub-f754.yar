rule TTP_XOR_MULT_DOSStub_f754 {
  strings:
    $key_f754 = { a3 3c [2] d7 24 [2] 90 26 [2] d7 37 [2] 99 3b [2] 95 31 [2] 82 3a [2] 99 74 [2] a4 }

  condition:
    any of them
}