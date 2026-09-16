rule TTP_XOR_MULT_DOSStub_c2aa {
  strings:
    $key_c2aa = { 96 c2 [2] e2 da [2] a5 d8 [2] e2 c9 [2] ac c5 [2] a0 cf [2] b7 c4 [2] ac 8a [2] 91 }

  condition:
    any of them
}