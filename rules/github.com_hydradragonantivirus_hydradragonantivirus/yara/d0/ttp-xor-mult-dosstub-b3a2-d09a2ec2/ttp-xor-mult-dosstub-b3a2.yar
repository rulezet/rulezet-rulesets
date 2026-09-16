rule TTP_XOR_MULT_DOSStub_b3a2 {
  strings:
    $key_b3a2 = { e7 ca [2] 93 d2 [2] d4 d0 [2] 93 c1 [2] dd cd [2] d1 c7 [2] c6 cc [2] dd 82 [2] e0 }

  condition:
    any of them
}