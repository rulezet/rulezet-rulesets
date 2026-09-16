rule TTP_XOR_MULT_DOSStub_20a9 {
  strings:
    $key_20a9 = { 74 c1 [2] 00 d9 [2] 47 db [2] 00 ca [2] 4e c6 [2] 42 cc [2] 55 c7 [2] 4e 89 [2] 73 }

  condition:
    any of them
}