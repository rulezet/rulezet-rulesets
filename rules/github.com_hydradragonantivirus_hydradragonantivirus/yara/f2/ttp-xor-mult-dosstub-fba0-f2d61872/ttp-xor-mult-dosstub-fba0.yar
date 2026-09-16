rule TTP_XOR_MULT_DOSStub_fba0 {
  strings:
    $key_fba0 = { af c8 [2] db d0 [2] 9c d2 [2] db c3 [2] 95 cf [2] 99 c5 [2] 8e ce [2] 95 80 [2] a8 }

  condition:
    any of them
}