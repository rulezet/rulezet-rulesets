rule TTP_XOR_MULT_DOSStub_edd7 {
  strings:
    $key_edd7 = { b9 bf [2] cd a7 [2] 8a a5 [2] cd b4 [2] 83 b8 [2] 8f b2 [2] 98 b9 [2] 83 f7 [2] be }

  condition:
    any of them
}