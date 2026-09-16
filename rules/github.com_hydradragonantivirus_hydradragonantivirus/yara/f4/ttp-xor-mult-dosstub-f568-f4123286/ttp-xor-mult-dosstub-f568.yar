rule TTP_XOR_MULT_DOSStub_f568 {
  strings:
    $key_f568 = { a1 00 [2] d5 18 [2] 92 1a [2] d5 0b [2] 9b 07 [2] 97 0d [2] 80 06 [2] 9b 48 [2] a6 }

  condition:
    any of them
}