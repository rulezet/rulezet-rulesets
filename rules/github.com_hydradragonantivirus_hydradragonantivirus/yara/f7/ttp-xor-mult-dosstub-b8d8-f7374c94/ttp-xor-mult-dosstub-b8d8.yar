rule TTP_XOR_MULT_DOSStub_b8d8 {
  strings:
    $key_b8d8 = { ec b0 [2] 98 a8 [2] df aa [2] 98 bb [2] d6 b7 [2] da bd [2] cd b6 [2] d6 f8 [2] eb }

  condition:
    any of them
}