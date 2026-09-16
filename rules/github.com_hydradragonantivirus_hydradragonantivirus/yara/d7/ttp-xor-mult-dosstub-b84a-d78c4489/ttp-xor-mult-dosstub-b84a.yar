rule TTP_XOR_MULT_DOSStub_b84a {
  strings:
    $key_b84a = { ec 22 [2] 98 3a [2] df 38 [2] 98 29 [2] d6 25 [2] da 2f [2] cd 24 [2] d6 6a [2] eb }

  condition:
    any of them
}