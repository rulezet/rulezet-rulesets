rule TTP_XOR_MULT_DOSStub_1416 {
  strings:
    $key_1416 = { 40 7e [2] 34 66 [2] 73 64 [2] 34 75 [2] 7a 79 [2] 76 73 [2] 61 78 [2] 7a 36 [2] 47 }

  condition:
    any of them
}