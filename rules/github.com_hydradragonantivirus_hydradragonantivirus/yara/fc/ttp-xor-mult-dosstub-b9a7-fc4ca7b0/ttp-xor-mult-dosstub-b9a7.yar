rule TTP_XOR_MULT_DOSStub_b9a7 {
  strings:
    $key_b9a7 = { ed cf [2] 99 d7 [2] de d5 [2] 99 c4 [2] d7 c8 [2] db c2 [2] cc c9 [2] d7 87 [2] ea }

  condition:
    any of them
}