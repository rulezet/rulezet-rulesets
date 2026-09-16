rule TTP_XOR_MULT_DOSStub_ed58 {
  strings:
    $key_ed58 = { b9 30 [2] cd 28 [2] 8a 2a [2] cd 3b [2] 83 37 [2] 8f 3d [2] 98 36 [2] 83 78 [2] be }

  condition:
    any of them
}