rule TTP_XOR_MULT_DOSStub_b8f2 {
  strings:
    $key_b8f2 = { ec 9a [2] 98 82 [2] df 80 [2] 98 91 [2] d6 9d [2] da 97 [2] cd 9c [2] d6 d2 [2] eb }

  condition:
    any of them
}