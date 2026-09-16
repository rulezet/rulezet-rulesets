rule TTP_XOR_MULT_DOSStub_5517 {
  strings:
    $key_5517 = { 01 7f [2] 75 67 [2] 32 65 [2] 75 74 [2] 3b 78 [2] 37 72 [2] 20 79 [2] 3b 37 [2] 06 }

  condition:
    any of them
}