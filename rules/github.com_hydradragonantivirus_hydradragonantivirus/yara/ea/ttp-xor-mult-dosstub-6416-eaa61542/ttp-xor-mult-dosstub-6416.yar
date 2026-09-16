rule TTP_XOR_MULT_DOSStub_6416 {
  strings:
    $key_6416 = { 30 7e [2] 44 66 [2] 03 64 [2] 44 75 [2] 0a 79 [2] 06 73 [2] 11 78 [2] 0a 36 [2] 37 }

  condition:
    any of them
}