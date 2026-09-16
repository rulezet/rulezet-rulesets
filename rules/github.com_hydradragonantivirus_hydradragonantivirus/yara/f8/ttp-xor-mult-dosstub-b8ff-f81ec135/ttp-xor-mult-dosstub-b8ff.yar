rule TTP_XOR_MULT_DOSStub_b8ff {
  strings:
    $key_b8ff = { ec 97 [2] 98 8f [2] df 8d [2] 98 9c [2] d6 90 [2] da 9a [2] cd 91 [2] d6 df [2] eb }

  condition:
    any of them
}