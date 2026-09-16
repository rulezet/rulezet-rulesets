rule TTP_XOR_MULT_DOSStub_31a2 {
  strings:
    $key_31a2 = { 65 ca [2] 11 d2 [2] 56 d0 [2] 11 c1 [2] 5f cd [2] 53 c7 [2] 44 cc [2] 5f 82 [2] 62 }

  condition:
    any of them
}