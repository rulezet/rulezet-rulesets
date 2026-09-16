rule TTP_XOR_MULT_DOSStub_5511 {
  strings:
    $key_5511 = { 01 79 [2] 75 61 [2] 32 63 [2] 75 72 [2] 3b 7e [2] 37 74 [2] 20 7f [2] 3b 31 [2] 06 }

  condition:
    any of them
}