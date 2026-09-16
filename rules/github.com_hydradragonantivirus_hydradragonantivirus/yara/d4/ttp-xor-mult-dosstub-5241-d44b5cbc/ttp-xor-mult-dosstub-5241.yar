rule TTP_XOR_MULT_DOSStub_5241 {
  strings:
    $key_5241 = { 06 29 [2] 72 31 [2] 35 33 [2] 72 22 [2] 3c 2e [2] 30 24 [2] 27 2f [2] 3c 61 [2] 01 }

  condition:
    any of them
}