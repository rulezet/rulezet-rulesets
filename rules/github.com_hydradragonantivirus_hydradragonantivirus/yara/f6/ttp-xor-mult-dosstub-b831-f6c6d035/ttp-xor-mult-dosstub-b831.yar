rule TTP_XOR_MULT_DOSStub_b831 {
  strings:
    $key_b831 = { ec 59 [2] 98 41 [2] df 43 [2] 98 52 [2] d6 5e [2] da 54 [2] cd 5f [2] d6 11 [2] eb }

  condition:
    any of them
}