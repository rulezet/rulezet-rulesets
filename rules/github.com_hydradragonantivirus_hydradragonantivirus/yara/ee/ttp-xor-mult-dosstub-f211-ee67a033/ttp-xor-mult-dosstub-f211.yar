rule TTP_XOR_MULT_DOSStub_f211 {
  strings:
    $key_f211 = { a6 79 [2] d2 61 [2] 95 63 [2] d2 72 [2] 9c 7e [2] 90 74 [2] 87 7f [2] 9c 31 [2] a1 }

  condition:
    any of them
}