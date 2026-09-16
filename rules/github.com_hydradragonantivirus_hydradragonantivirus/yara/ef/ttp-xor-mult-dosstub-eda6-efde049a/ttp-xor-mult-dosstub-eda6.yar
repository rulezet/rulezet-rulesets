rule TTP_XOR_MULT_DOSStub_eda6 {
  strings:
    $key_eda6 = { b9 ce [2] cd d6 [2] 8a d4 [2] cd c5 [2] 83 c9 [2] 8f c3 [2] 98 c8 [2] 83 86 [2] be }

  condition:
    any of them
}