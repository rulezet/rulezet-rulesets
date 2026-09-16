rule TTP_XOR_MULT_DOSStub_b850 {
  strings:
    $key_b850 = { ec 38 [2] 98 20 [2] df 22 [2] 98 33 [2] d6 3f [2] da 35 [2] cd 3e [2] d6 70 [2] eb }

  condition:
    any of them
}