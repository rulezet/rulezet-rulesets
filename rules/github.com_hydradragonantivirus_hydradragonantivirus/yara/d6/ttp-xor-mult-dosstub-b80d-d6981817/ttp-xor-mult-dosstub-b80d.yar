rule TTP_XOR_MULT_DOSStub_b80d {
  strings:
    $key_b80d = { ec 65 [2] 98 7d [2] df 7f [2] 98 6e [2] d6 62 [2] da 68 [2] cd 63 [2] d6 2d [2] eb }

  condition:
    any of them
}