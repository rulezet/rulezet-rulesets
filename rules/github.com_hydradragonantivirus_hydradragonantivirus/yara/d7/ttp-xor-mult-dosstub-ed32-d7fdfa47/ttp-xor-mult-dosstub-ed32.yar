rule TTP_XOR_MULT_DOSStub_ed32 {
  strings:
    $key_ed32 = { b9 5a [2] cd 42 [2] 8a 40 [2] cd 51 [2] 83 5d [2] 8f 57 [2] 98 5c [2] 83 12 [2] be }

  condition:
    any of them
}