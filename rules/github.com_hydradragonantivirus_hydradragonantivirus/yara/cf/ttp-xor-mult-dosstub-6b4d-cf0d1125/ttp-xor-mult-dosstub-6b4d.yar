rule TTP_XOR_MULT_DOSStub_6b4d {
  strings:
    $key_6b4d = { 3f 25 [2] 4b 3d [2] 0c 3f [2] 4b 2e [2] 05 22 [2] 09 28 [2] 1e 23 [2] 05 6d [2] 38 }

  condition:
    any of them
}