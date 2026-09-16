rule TTP_XOR_MULT_DOSStub_ed3a {
  strings:
    $key_ed3a = { b9 52 [2] cd 4a [2] 8a 48 [2] cd 59 [2] 83 55 [2] 8f 5f [2] 98 54 [2] 83 1a [2] be }

  condition:
    any of them
}