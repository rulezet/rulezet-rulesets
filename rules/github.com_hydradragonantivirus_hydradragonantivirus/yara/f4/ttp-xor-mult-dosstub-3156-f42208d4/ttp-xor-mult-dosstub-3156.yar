rule TTP_XOR_MULT_DOSStub_3156 {
  strings:
    $key_3156 = { 65 3e [2] 11 26 [2] 56 24 [2] 11 35 [2] 5f 39 [2] 53 33 [2] 44 38 [2] 5f 76 [2] 62 }

  condition:
    any of them
}