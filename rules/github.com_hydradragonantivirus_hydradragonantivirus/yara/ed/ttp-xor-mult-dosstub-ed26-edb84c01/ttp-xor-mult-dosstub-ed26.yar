rule TTP_XOR_MULT_DOSStub_ed26 {
  strings:
    $key_ed26 = { b9 4e [2] cd 56 [2] 8a 54 [2] cd 45 [2] 83 49 [2] 8f 43 [2] 98 48 [2] 83 06 [2] be }

  condition:
    any of them
}