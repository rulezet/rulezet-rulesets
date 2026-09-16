rule TTP_XOR_MULT_DOSStub_b85d {
  strings:
    $key_b85d = { ec 35 [2] 98 2d [2] df 2f [2] 98 3e [2] d6 32 [2] da 38 [2] cd 33 [2] d6 7d [2] eb }

  condition:
    any of them
}