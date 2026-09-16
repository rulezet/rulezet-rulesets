rule TTP_XOR_MULT_DOSStub_214d {
  strings:
    $key_214d = { 75 25 [2] 01 3d [2] 46 3f [2] 01 2e [2] 4f 22 [2] 43 28 [2] 54 23 [2] 4f 6d [2] 72 }

  condition:
    any of them
}