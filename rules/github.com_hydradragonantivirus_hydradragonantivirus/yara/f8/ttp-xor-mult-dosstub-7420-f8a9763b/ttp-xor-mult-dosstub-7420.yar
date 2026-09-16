rule TTP_XOR_MULT_DOSStub_7420 {
  strings:
    $key_7420 = { 20 48 [2] 54 50 [2] 13 52 [2] 54 43 [2] 1a 4f [2] 16 45 [2] 01 4e [2] 1a 00 [2] 27 }

  condition:
    any of them
}