rule TTP_XOR_MULT_DOSStub_0aa0 {
  strings:
    $key_0aa0 = { 5e c8 [2] 2a d0 [2] 6d d2 [2] 2a c3 [2] 64 cf [2] 68 c5 [2] 7f ce [2] 64 80 [2] 59 }

  condition:
    any of them
}