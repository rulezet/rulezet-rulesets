rule TTP_XOR_MULT_DOSStub_1656 {
  strings:
    $key_1656 = { 42 3e [2] 36 26 [2] 71 24 [2] 36 35 [2] 78 39 [2] 74 33 [2] 63 38 [2] 78 76 [2] 45 }

  condition:
    any of them
}