rule TTP_XOR_MULT_DOSStub_5216 {
  strings:
    $key_5216 = { 06 7e [2] 72 66 [2] 35 64 [2] 72 75 [2] 3c 79 [2] 30 73 [2] 27 78 [2] 3c 36 [2] 01 }

  condition:
    any of them
}