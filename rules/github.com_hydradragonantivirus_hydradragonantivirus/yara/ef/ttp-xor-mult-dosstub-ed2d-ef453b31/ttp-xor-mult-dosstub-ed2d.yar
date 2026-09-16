rule TTP_XOR_MULT_DOSStub_ed2d {
  strings:
    $key_ed2d = { b9 45 [2] cd 5d [2] 8a 5f [2] cd 4e [2] 83 42 [2] 8f 48 [2] 98 43 [2] 83 0d [2] be }

  condition:
    any of them
}