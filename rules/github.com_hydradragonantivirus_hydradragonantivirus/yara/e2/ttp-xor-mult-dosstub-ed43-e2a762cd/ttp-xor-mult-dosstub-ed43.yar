rule TTP_XOR_MULT_DOSStub_ed43 {
  strings:
    $key_ed43 = { b9 2b [2] cd 33 [2] 8a 31 [2] cd 20 [2] 83 2c [2] 8f 26 [2] 98 2d [2] 83 63 [2] be }

  condition:
    any of them
}