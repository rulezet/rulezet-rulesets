rule TTP_XOR_MULT_DOSStub_e5a2 {
  strings:
    $key_e5a2 = { b1 ca [2] c5 d2 [2] 82 d0 [2] c5 c1 [2] 8b cd [2] 87 c7 [2] 90 cc [2] 8b 82 [2] b6 }

  condition:
    any of them
}