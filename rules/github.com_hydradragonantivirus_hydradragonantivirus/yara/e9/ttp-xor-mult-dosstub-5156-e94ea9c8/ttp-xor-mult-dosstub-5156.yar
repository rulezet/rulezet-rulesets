rule TTP_XOR_MULT_DOSStub_5156 {
  strings:
    $key_5156 = { 05 3e [2] 71 26 [2] 36 24 [2] 71 35 [2] 3f 39 [2] 33 33 [2] 24 38 [2] 3f 76 [2] 02 }

  condition:
    any of them
}