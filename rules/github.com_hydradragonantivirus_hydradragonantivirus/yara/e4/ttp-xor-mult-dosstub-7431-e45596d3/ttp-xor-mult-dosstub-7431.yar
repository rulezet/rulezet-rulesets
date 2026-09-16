rule TTP_XOR_MULT_DOSStub_7431 {
  strings:
    $key_7431 = { 20 59 [2] 54 41 [2] 13 43 [2] 54 52 [2] 1a 5e [2] 16 54 [2] 01 5f [2] 1a 11 [2] 27 }

  condition:
    any of them
}