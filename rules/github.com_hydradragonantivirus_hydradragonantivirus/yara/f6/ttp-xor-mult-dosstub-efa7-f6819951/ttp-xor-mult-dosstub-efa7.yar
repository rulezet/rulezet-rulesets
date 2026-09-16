rule TTP_XOR_MULT_DOSStub_efa7 {
  strings:
    $key_efa7 = { bb cf [2] cf d7 [2] 88 d5 [2] cf c4 [2] 81 c8 [2] 8d c2 [2] 9a c9 [2] 81 87 [2] bc }

  condition:
    any of them
}