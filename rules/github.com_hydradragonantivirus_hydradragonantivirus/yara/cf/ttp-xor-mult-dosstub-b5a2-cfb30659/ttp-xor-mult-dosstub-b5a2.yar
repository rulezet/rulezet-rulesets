rule TTP_XOR_MULT_DOSStub_b5a2 {
  strings:
    $key_b5a2 = { e1 ca [2] 95 d2 [2] d2 d0 [2] 95 c1 [2] db cd [2] d7 c7 [2] c0 cc [2] db 82 [2] e6 }

  condition:
    any of them
}