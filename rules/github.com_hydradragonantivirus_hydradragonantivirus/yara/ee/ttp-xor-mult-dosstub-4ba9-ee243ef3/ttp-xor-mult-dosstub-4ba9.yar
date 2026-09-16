rule TTP_XOR_MULT_DOSStub_4ba9 {
  strings:
    $key_4ba9 = { 1f c1 [2] 6b d9 [2] 2c db [2] 6b ca [2] 25 c6 [2] 29 cc [2] 3e c7 [2] 25 89 [2] 18 }

  condition:
    any of them
}