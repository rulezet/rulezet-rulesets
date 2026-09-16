rule TTP_XOR_MULT_DOSStub_f278 {
  strings:
    $key_f278 = { a6 10 [2] d2 08 [2] 95 0a [2] d2 1b [2] 9c 17 [2] 90 1d [2] 87 16 [2] 9c 58 [2] a1 }

  condition:
    any of them
}