rule TTP_XOR_MULT_DOSStub_b86f {
  strings:
    $key_b86f = { ec 07 [2] 98 1f [2] df 1d [2] 98 0c [2] d6 00 [2] da 0a [2] cd 01 [2] d6 4f [2] eb }

  condition:
    any of them
}