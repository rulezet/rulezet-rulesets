rule TTP_XOR_MULT_DOSStub_b8f8 {
  strings:
    $key_b8f8 = { ec 90 [2] 98 88 [2] df 8a [2] 98 9b [2] d6 97 [2] da 9d [2] cd 96 [2] d6 d8 [2] eb }

  condition:
    any of them
}