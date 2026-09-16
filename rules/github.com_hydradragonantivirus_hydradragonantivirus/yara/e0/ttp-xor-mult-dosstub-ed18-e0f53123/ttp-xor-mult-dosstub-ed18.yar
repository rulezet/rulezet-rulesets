rule TTP_XOR_MULT_DOSStub_ed18 {
  strings:
    $key_ed18 = { b9 70 [2] cd 68 [2] 8a 6a [2] cd 7b [2] 83 77 [2] 8f 7d [2] 98 76 [2] 83 38 [2] be }

  condition:
    any of them
}