rule TTP_XOR_MULT_DOSStub_7ba9 {
  strings:
    $key_7ba9 = { 2f c1 [2] 5b d9 [2] 1c db [2] 5b ca [2] 15 c6 [2] 19 cc [2] 0e c7 [2] 15 89 [2] 28 }

  condition:
    any of them
}