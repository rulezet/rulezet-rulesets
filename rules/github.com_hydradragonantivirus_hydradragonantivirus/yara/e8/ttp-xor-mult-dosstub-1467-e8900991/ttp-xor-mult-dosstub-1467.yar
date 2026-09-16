rule TTP_XOR_MULT_DOSStub_1467 {
  strings:
    $key_1467 = { 40 0f [2] 34 17 [2] 73 15 [2] 34 04 [2] 7a 08 [2] 76 02 [2] 61 09 [2] 7a 47 [2] 47 }

  condition:
    any of them
}