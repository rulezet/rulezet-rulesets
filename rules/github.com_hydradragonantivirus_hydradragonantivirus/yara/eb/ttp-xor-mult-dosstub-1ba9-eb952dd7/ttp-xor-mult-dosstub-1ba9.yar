rule TTP_XOR_MULT_DOSStub_1ba9 {
  strings:
    $key_1ba9 = { 4f c1 [2] 3b d9 [2] 7c db [2] 3b ca [2] 75 c6 [2] 79 cc [2] 6e c7 [2] 75 89 [2] 48 }

  condition:
    any of them
}