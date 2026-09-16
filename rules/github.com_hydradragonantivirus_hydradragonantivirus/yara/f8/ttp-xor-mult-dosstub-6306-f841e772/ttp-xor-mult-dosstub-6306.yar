rule TTP_XOR_MULT_DOSStub_6306 {
  strings:
    $key_6306 = { 37 6e [2] 43 76 [2] 04 74 [2] 43 65 [2] 0d 69 [2] 01 63 [2] 16 68 [2] 0d 26 [2] 30 }

  condition:
    any of them
}