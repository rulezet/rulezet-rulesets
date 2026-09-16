rule TTP_XOR_MULT_DOSStub_76a9 {
  strings:
    $key_76a9 = { 22 c1 [2] 56 d9 [2] 11 db [2] 56 ca [2] 18 c6 [2] 14 cc [2] 03 c7 [2] 18 89 [2] 25 }

  condition:
    any of them
}