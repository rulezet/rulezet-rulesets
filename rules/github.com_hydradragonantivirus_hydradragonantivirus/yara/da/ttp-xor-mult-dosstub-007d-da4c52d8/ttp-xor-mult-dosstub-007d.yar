rule TTP_XOR_MULT_DOSStub_007d {
  strings:
    $key_007d = { 54 15 [2] 20 0d [2] 67 0f [2] 20 1e [2] 6e 12 [2] 62 18 [2] 75 13 [2] 6e 5d [2] 53 }

  condition:
    any of them
}