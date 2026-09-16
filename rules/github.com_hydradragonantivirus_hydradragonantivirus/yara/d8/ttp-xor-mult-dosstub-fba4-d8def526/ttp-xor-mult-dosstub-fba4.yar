rule TTP_XOR_MULT_DOSStub_fba4 {
  strings:
    $key_fba4 = { af cc [2] db d4 [2] 9c d6 [2] db c7 [2] 95 cb [2] 99 c1 [2] 8e ca [2] 95 84 [2] a8 }

  condition:
    any of them
}