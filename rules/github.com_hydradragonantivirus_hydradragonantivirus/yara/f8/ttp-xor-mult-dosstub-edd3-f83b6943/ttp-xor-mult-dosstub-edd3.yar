rule TTP_XOR_MULT_DOSStub_edd3 {
  strings:
    $key_edd3 = { b9 bb [2] cd a3 [2] 8a a1 [2] cd b0 [2] 83 bc [2] 8f b6 [2] 98 bd [2] 83 f3 [2] be }

  condition:
    any of them
}