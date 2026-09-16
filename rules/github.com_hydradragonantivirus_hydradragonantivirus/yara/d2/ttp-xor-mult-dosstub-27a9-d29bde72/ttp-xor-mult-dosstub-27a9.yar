rule TTP_XOR_MULT_DOSStub_27a9 {
  strings:
    $key_27a9 = { 73 c1 [2] 07 d9 [2] 40 db [2] 07 ca [2] 49 c6 [2] 45 cc [2] 52 c7 [2] 49 89 [2] 74 }

  condition:
    any of them
}