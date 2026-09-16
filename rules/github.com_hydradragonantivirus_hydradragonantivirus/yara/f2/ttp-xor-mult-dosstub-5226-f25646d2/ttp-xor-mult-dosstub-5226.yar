rule TTP_XOR_MULT_DOSStub_5226 {
  strings:
    $key_5226 = { 06 4e [2] 72 56 [2] 35 54 [2] 72 45 [2] 3c 49 [2] 30 43 [2] 27 48 [2] 3c 06 [2] 01 }

  condition:
    any of them
}