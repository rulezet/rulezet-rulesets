rule TTP_XOR_MULT_DOSStub_edd6 {
  strings:
    $key_edd6 = { b9 be [2] cd a6 [2] 8a a4 [2] cd b5 [2] 83 b9 [2] 8f b3 [2] 98 b8 [2] 83 f6 [2] be }

  condition:
    any of them
}