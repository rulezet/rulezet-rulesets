rule TTP_XOR_MULT_DOSStub_b2a2 {
  strings:
    $key_b2a2 = { e6 ca [2] 92 d2 [2] d5 d0 [2] 92 c1 [2] dc cd [2] d0 c7 [2] c7 cc [2] dc 82 [2] e1 }

  condition:
    any of them
}