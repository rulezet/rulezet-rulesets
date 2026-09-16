rule TTP_XOR_MULT_DOSStub_ed57 {
  strings:
    $key_ed57 = { b9 3f [2] cd 27 [2] 8a 25 [2] cd 34 [2] 83 38 [2] 8f 32 [2] 98 39 [2] 83 77 [2] be }

  condition:
    any of them
}