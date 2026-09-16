rule TTP_XOR_MULT_DOSStub_c2a7 {
  strings:
    $key_c2a7 = { 96 cf [2] e2 d7 [2] a5 d5 [2] e2 c4 [2] ac c8 [2] a0 c2 [2] b7 c9 [2] ac 87 [2] 91 }

  condition:
    any of them
}