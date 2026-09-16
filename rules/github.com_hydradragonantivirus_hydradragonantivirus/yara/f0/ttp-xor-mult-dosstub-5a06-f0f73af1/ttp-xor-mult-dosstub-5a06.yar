rule TTP_XOR_MULT_DOSStub_5a06 {
  strings:
    $key_5a06 = { 0e 6e [2] 7a 76 [2] 3d 74 [2] 7a 65 [2] 34 69 [2] 38 63 [2] 2f 68 [2] 34 26 [2] 09 }

  condition:
    any of them
}