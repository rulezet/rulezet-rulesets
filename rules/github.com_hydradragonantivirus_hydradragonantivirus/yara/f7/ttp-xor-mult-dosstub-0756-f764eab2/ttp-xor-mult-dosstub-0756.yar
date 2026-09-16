rule TTP_XOR_MULT_DOSStub_0756 {
  strings:
    $key_0756 = { 53 3e [2] 27 26 [2] 60 24 [2] 27 35 [2] 69 39 [2] 65 33 [2] 72 38 [2] 69 76 [2] 54 }

  condition:
    any of them
}