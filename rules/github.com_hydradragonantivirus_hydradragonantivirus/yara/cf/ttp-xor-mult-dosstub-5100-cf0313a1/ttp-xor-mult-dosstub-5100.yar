rule TTP_XOR_MULT_DOSStub_5100 {
  strings:
    $key_5100 = { 05 68 [2] 71 70 [2] 36 72 [2] 71 63 [2] 3f 6f [2] 33 65 [2] 24 6e [2] 3f 20 [2] 02 }

  condition:
    any of them
}