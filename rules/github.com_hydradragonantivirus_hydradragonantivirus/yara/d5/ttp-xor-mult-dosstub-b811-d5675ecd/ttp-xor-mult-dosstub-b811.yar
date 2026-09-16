rule TTP_XOR_MULT_DOSStub_b811 {
  strings:
    $key_b811 = { ec 79 [2] 98 61 [2] df 63 [2] 98 72 [2] d6 7e [2] da 74 [2] cd 7f [2] d6 31 [2] eb }

  condition:
    any of them
}