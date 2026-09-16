rule TTP_XOR_MULT_DOSStub_f268 {
  strings:
    $key_f268 = { a6 00 [2] d2 18 [2] 95 1a [2] d2 0b [2] 9c 07 [2] 90 0d [2] 87 06 [2] 9c 48 [2] a1 }

  condition:
    any of them
}