rule TTP_XOR_MULT_DOSStub_1417 {
  strings:
    $key_1417 = { 40 7f [2] 34 67 [2] 73 65 [2] 34 74 [2] 7a 78 [2] 76 72 [2] 61 79 [2] 7a 37 [2] 47 }

  condition:
    any of them
}