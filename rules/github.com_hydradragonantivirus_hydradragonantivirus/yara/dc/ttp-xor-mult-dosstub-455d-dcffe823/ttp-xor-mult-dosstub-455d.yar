rule TTP_XOR_MULT_DOSStub_455d {
  strings:
    $key_455d = { 11 35 [2] 65 2d [2] 22 2f [2] 65 3e [2] 2b 32 [2] 27 38 [2] 30 33 [2] 2b 7d [2] 16 }

  condition:
    any of them
}