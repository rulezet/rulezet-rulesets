rule TTP_XOR_MULT_DOSStub_fba5 {
  strings:
    $key_fba5 = { af cd [2] db d5 [2] 9c d7 [2] db c6 [2] 95 ca [2] 99 c0 [2] 8e cb [2] 95 85 [2] a8 }

  condition:
    any of them
}