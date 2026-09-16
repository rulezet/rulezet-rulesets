rule TTP_XOR_MULT_DOSStub_1411 {
  strings:
    $key_1411 = { 40 79 [2] 34 61 [2] 73 63 [2] 34 72 [2] 7a 7e [2] 76 74 [2] 61 7f [2] 7a 31 [2] 47 }

  condition:
    any of them
}