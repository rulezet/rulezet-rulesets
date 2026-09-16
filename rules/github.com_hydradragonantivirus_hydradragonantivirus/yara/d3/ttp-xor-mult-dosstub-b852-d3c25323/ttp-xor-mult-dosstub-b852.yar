rule TTP_XOR_MULT_DOSStub_b852 {
  strings:
    $key_b852 = { ec 3a [2] 98 22 [2] df 20 [2] 98 31 [2] d6 3d [2] da 37 [2] cd 3c [2] d6 72 [2] eb }

  condition:
    any of them
}