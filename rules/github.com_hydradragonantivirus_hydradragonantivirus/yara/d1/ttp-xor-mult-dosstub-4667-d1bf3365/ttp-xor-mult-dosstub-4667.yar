rule TTP_XOR_MULT_DOSStub_4667 {
  strings:
    $key_4667 = { 12 0f [2] 66 17 [2] 21 15 [2] 66 04 [2] 28 08 [2] 24 02 [2] 33 09 [2] 28 47 [2] 15 }

  condition:
    any of them
}