rule TTP_XOR_MULT_DOSStub_4d4d {
  strings:
    $key_4d4d = { 19 25 [2] 6d 3d [2] 2a 3f [2] 6d 2e [2] 23 22 [2] 2f 28 [2] 38 23 [2] 23 6d [2] 1e }

  condition:
    any of them
}