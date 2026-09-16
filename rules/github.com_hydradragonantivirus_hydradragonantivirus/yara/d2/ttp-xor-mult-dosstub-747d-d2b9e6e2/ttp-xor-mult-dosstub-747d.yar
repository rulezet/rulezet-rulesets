rule TTP_XOR_MULT_DOSStub_747d {
  strings:
    $key_747d = { 20 15 [2] 54 0d [2] 13 0f [2] 54 1e [2] 1a 12 [2] 16 18 [2] 01 13 [2] 1a 5d [2] 27 }

  condition:
    any of them
}