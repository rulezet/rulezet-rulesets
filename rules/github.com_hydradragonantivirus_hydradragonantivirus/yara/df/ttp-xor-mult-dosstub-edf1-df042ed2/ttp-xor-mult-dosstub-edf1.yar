rule TTP_XOR_MULT_DOSStub_edf1 {
  strings:
    $key_edf1 = { b9 99 [2] cd 81 [2] 8a 83 [2] cd 92 [2] 83 9e [2] 8f 94 [2] 98 9f [2] 83 d1 [2] be }

  condition:
    any of them
}