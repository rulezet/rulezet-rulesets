rule TTP_XOR_MULT_DOSStub_030d {
  strings:
    $key_030d = { 57 65 [2] 23 7d [2] 64 7f [2] 23 6e [2] 6d 62 [2] 61 68 [2] 76 63 [2] 6d 2d [2] 50 }

  condition:
    any of them
}