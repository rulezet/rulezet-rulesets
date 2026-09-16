rule TTP_XOR_MULT_DOSStub_f261 {
  strings:
    $key_f261 = { a6 09 [2] d2 11 [2] 95 13 [2] d2 02 [2] 9c 0e [2] 90 04 [2] 87 0f [2] 9c 41 [2] a1 }

  condition:
    any of them
}