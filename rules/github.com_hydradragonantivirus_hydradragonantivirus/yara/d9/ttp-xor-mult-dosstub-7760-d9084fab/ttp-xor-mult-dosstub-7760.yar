rule TTP_XOR_MULT_DOSStub_7760 {
  strings:
    $key_7760 = { 23 08 [2] 57 10 [2] 10 12 [2] 57 03 [2] 19 0f [2] 15 05 [2] 02 0e [2] 19 40 [2] 24 }

  condition:
    any of them
}