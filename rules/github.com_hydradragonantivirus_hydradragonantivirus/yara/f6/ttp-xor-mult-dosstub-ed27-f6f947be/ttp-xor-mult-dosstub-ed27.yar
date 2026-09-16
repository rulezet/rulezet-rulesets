rule TTP_XOR_MULT_DOSStub_ed27 {
  strings:
    $key_ed27 = { b9 4f [2] cd 57 [2] 8a 55 [2] cd 44 [2] 83 48 [2] 8f 42 [2] 98 49 [2] 83 07 [2] be }

  condition:
    any of them
}