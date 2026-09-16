rule TTP_XOR_MULT_DOSStub_7c1d {
  strings:
    $key_7c1d = { 28 75 [2] 5c 6d [2] 1b 6f [2] 5c 7e [2] 12 72 [2] 1e 78 [2] 09 73 [2] 12 3d [2] 2f }

  condition:
    any of them
}