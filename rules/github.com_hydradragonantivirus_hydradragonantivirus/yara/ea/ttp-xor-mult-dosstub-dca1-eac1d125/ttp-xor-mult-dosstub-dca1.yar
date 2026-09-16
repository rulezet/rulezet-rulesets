rule TTP_XOR_MULT_DOSStub_dca1 {
  strings:
    $key_dca1 = { 88 c9 [2] fc d1 [2] bb d3 [2] fc c2 [2] b2 ce [2] be c4 [2] a9 cf [2] b2 81 [2] 8f }

  condition:
    any of them
}