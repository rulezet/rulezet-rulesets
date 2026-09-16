rule TTP_XOR_MULT_DOSStub_3561 {
  strings:
    $key_3561 = { 61 09 [2] 15 11 [2] 52 13 [2] 15 02 [2] 5b 0e [2] 57 04 [2] 40 0f [2] 5b 41 [2] 66 }

  condition:
    any of them
}