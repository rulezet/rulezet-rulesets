rule TTP_XOR_MULT_DOSStub_6077 {
  strings:
    $key_6077 = { 34 1f [2] 40 07 [2] 07 05 [2] 40 14 [2] 0e 18 [2] 02 12 [2] 15 19 [2] 0e 57 [2] 33 }

  condition:
    any of them
}