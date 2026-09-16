rule TTP_XOR_MULT_DOSStub_b81d {
  strings:
    $key_b81d = { ec 75 [2] 98 6d [2] df 6f [2] 98 7e [2] d6 72 [2] da 78 [2] cd 73 [2] d6 3d [2] eb }

  condition:
    any of them
}