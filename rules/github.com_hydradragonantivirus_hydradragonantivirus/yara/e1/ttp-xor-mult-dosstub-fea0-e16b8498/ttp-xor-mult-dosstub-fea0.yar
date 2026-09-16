rule TTP_XOR_MULT_DOSStub_fea0 {
  strings:
    $key_fea0 = { aa c8 [2] de d0 [2] 99 d2 [2] de c3 [2] 90 cf [2] 9c c5 [2] 8b ce [2] 90 80 [2] ad }

  condition:
    any of them
}