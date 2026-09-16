rule TTP_XOR_MULT_DOSStub_ed03 {
  strings:
    $key_ed03 = { b9 6b [2] cd 73 [2] 8a 71 [2] cd 60 [2] 83 6c [2] 8f 66 [2] 98 6d [2] 83 23 [2] be }

  condition:
    any of them
}