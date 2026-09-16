rule TTP_XOR_MULT_DOSStub_0aa7 {
  strings:
    $key_0aa7 = { 5e cf [2] 2a d7 [2] 6d d5 [2] 2a c4 [2] 64 c8 [2] 68 c2 [2] 7f c9 [2] 64 87 [2] 59 }

  condition:
    any of them
}