rule TTP_XOR_MULT_DOSStub_5a2d {
  strings:
    $key_5a2d = { 0e 45 [2] 7a 5d [2] 3d 5f [2] 7a 4e [2] 34 42 [2] 38 48 [2] 2f 43 [2] 34 0d [2] 09 }

  condition:
    any of them
}