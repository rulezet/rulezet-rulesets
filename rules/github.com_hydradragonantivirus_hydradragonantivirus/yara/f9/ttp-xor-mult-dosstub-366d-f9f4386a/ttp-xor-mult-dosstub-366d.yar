rule TTP_XOR_MULT_DOSStub_366d {
  strings:
    $key_366d = { 62 05 [2] 16 1d [2] 51 1f [2] 16 0e [2] 58 02 [2] 54 08 [2] 43 03 [2] 58 4d [2] 65 }

  condition:
    any of them
}