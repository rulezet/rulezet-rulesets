rule TTP_XOR_MULT_DOSStub_60a9 {
  strings:
    $key_60a9 = { 34 c1 [2] 40 d9 [2] 07 db [2] 40 ca [2] 0e c6 [2] 02 cc [2] 15 c7 [2] 0e 89 [2] 33 }

  condition:
    any of them
}