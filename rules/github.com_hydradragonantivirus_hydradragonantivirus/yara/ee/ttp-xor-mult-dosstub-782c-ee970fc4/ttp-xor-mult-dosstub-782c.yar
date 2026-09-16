rule TTP_XOR_MULT_DOSStub_782c {
  strings:
    $key_782c = { 2c 44 [2] 58 5c [2] 1f 5e [2] 58 4f [2] 16 43 [2] 1a 49 [2] 0d 42 [2] 16 0c [2] 2b }

  condition:
    any of them
}