rule TTP_XOR_MULT_DOSStub_ed4e {
  strings:
    $key_ed4e = { b9 26 [2] cd 3e [2] 8a 3c [2] cd 2d [2] 83 21 [2] 8f 2b [2] 98 20 [2] 83 6e [2] be }

  condition:
    any of them
}