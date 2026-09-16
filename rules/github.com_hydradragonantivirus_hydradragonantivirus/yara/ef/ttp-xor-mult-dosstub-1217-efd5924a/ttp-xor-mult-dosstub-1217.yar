rule TTP_XOR_MULT_DOSStub_1217 {
  strings:
    $key_1217 = { 46 7f [2] 32 67 [2] 75 65 [2] 32 74 [2] 7c 78 [2] 70 72 [2] 67 79 [2] 7c 37 [2] 41 }

  condition:
    any of them
}