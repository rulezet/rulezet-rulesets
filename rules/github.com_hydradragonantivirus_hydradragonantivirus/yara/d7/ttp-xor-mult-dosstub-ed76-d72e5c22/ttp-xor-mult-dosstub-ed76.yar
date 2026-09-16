rule TTP_XOR_MULT_DOSStub_ed76 {
  strings:
    $key_ed76 = { b9 1e [2] cd 06 [2] 8a 04 [2] cd 15 [2] 83 19 [2] 8f 13 [2] 98 18 [2] 83 56 [2] be }

  condition:
    any of them
}