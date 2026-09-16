rule TTP_XOR_MULT_DOSStub_3a2d {
  strings:
    $key_3a2d = { 6e 45 [2] 1a 5d [2] 5d 5f [2] 1a 4e [2] 54 42 [2] 58 48 [2] 4f 43 [2] 54 0d [2] 69 }

  condition:
    any of them
}