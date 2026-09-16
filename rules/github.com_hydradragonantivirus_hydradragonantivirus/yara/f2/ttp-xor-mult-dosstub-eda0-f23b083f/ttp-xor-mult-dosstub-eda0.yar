rule TTP_XOR_MULT_DOSStub_eda0 {
  strings:
    $key_eda0 = { b9 c8 [2] cd d0 [2] 8a d2 [2] cd c3 [2] 83 cf [2] 8f c5 [2] 98 ce [2] 83 80 [2] be }

  condition:
    any of them
}