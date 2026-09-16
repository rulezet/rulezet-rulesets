rule TTP_XOR_MULT_DOSStub_e2a9 {
  strings:
    $key_e2a9 = { b6 c1 [2] c2 d9 [2] 85 db [2] c2 ca [2] 8c c6 [2] 80 cc [2] 97 c7 [2] 8c 89 [2] b1 }

  condition:
    any of them
}