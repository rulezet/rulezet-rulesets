rule TTP_XOR_MULT_DOSStub_036d {
  strings:
    $key_036d = { 57 05 [2] 23 1d [2] 64 1f [2] 23 0e [2] 6d 02 [2] 61 08 [2] 76 03 [2] 6d 4d [2] 50 }

  condition:
    any of them
}