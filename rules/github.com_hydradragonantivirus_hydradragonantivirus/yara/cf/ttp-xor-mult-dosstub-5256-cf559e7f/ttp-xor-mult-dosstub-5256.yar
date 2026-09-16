rule TTP_XOR_MULT_DOSStub_5256 {
  strings:
    $key_5256 = { 06 3e [2] 72 26 [2] 35 24 [2] 72 35 [2] 3c 39 [2] 30 33 [2] 27 38 [2] 3c 76 [2] 01 }

  condition:
    any of them
}