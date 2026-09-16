rule TTP_XOR_MULT_DOSStub_f275 {
  strings:
    $key_f275 = { a6 1d [2] d2 05 [2] 95 07 [2] d2 16 [2] 9c 1a [2] 90 10 [2] 87 1b [2] 9c 55 [2] a1 }

  condition:
    any of them
}