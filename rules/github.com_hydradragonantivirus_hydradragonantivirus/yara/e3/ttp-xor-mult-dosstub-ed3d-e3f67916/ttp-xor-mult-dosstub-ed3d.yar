rule TTP_XOR_MULT_DOSStub_ed3d {
  strings:
    $key_ed3d = { b9 55 [2] cd 4d [2] 8a 4f [2] cd 5e [2] 83 52 [2] 8f 58 [2] 98 53 [2] 83 1d [2] be }

  condition:
    any of them
}