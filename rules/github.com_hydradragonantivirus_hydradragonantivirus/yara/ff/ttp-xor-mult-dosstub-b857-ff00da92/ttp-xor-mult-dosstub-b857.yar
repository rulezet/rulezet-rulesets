rule TTP_XOR_MULT_DOSStub_b857 {
  strings:
    $key_b857 = { ec 3f [2] 98 27 [2] df 25 [2] 98 34 [2] d6 38 [2] da 32 [2] cd 39 [2] d6 77 [2] eb }

  condition:
    any of them
}