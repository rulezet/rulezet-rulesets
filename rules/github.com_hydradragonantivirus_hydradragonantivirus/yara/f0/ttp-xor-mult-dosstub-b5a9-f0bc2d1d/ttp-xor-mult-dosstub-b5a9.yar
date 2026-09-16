rule TTP_XOR_MULT_DOSStub_b5a9 {
  strings:
    $key_b5a9 = { e1 c1 [2] 95 d9 [2] d2 db [2] 95 ca [2] db c6 [2] d7 cc [2] c0 c7 [2] db 89 [2] e6 }

  condition:
    any of them
}