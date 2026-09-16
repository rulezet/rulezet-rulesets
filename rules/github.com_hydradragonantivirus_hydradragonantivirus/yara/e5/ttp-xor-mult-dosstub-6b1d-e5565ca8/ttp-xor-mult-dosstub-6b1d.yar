rule TTP_XOR_MULT_DOSStub_6b1d {
  strings:
    $key_6b1d = { 3f 75 [2] 4b 6d [2] 0c 6f [2] 4b 7e [2] 05 72 [2] 09 78 [2] 1e 73 [2] 05 3d [2] 38 }

  condition:
    any of them
}