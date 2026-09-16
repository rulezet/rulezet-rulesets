rule TTP_XOR_MULT_DOSStub_491d {
  strings:
    $key_491d = { 1d 75 [2] 69 6d [2] 2e 6f [2] 69 7e [2] 27 72 [2] 2b 78 [2] 3c 73 [2] 27 3d [2] 1a }

  condition:
    any of them
}