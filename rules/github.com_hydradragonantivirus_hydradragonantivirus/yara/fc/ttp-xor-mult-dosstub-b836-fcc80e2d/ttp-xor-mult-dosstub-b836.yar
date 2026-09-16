rule TTP_XOR_MULT_DOSStub_b836 {
  strings:
    $key_b836 = { ec 5e [2] 98 46 [2] df 44 [2] 98 55 [2] d6 59 [2] da 53 [2] cd 58 [2] d6 16 [2] eb }

  condition:
    any of them
}