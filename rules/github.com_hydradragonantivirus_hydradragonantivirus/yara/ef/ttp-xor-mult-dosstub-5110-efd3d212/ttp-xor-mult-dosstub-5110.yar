rule TTP_XOR_MULT_DOSStub_5110 {
  strings:
    $key_5110 = { 05 78 [2] 71 60 [2] 36 62 [2] 71 73 [2] 3f 7f [2] 33 75 [2] 24 7e [2] 3f 30 [2] 02 }

  condition:
    any of them
}