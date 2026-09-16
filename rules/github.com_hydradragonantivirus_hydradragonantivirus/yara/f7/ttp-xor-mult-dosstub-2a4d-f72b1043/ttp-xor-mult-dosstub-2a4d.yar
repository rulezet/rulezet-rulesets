rule TTP_XOR_MULT_DOSStub_2a4d {
  strings:
    $key_2a4d = { 7e 25 [2] 0a 3d [2] 4d 3f [2] 0a 2e [2] 44 22 [2] 48 28 [2] 5f 23 [2] 44 6d [2] 79 }

  condition:
    any of them
}