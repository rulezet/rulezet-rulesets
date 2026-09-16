rule TTP_XOR_MULT_DOSStub_14a9 {
  strings:
    $key_14a9 = { 40 c1 [2] 34 d9 [2] 73 db [2] 34 ca [2] 7a c6 [2] 76 cc [2] 61 c7 [2] 7a 89 [2] 47 }

  condition:
    any of them
}