rule TTP_XOR_MULT_DOSStub_f2a4 {
  strings:
    $key_f2a4 = { a6 cc [2] d2 d4 [2] 95 d6 [2] d2 c7 [2] 9c cb [2] 90 c1 [2] 87 ca [2] 9c 84 [2] a1 }

  condition:
    any of them
}