rule TTP_XOR_MULT_DOSStub_074d {
  strings:
    $key_074d = { 53 25 [2] 27 3d [2] 60 3f [2] 27 2e [2] 69 22 [2] 65 28 [2] 72 23 [2] 69 6d [2] 54 }

  condition:
    any of them
}