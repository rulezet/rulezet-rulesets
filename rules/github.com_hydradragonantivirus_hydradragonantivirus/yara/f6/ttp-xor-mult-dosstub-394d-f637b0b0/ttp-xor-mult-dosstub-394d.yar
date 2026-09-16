rule TTP_XOR_MULT_DOSStub_394d {
  strings:
    $key_394d = { 6d 25 [2] 19 3d [2] 5e 3f [2] 19 2e [2] 57 22 [2] 5b 28 [2] 4c 23 [2] 57 6d [2] 6a }

  condition:
    any of them
}