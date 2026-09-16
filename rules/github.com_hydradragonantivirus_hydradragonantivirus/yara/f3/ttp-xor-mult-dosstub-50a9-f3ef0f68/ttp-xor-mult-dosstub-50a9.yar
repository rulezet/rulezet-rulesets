rule TTP_XOR_MULT_DOSStub_50a9 {
  strings:
    $key_50a9 = { 04 c1 [2] 70 d9 [2] 37 db [2] 70 ca [2] 3e c6 [2] 32 cc [2] 25 c7 [2] 3e 89 [2] 03 }

  condition:
    any of them
}