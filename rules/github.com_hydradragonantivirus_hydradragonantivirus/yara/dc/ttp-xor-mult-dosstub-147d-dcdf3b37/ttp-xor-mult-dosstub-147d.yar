rule TTP_XOR_MULT_DOSStub_147d {
  strings:
    $key_147d = { 40 15 [2] 34 0d [2] 73 0f [2] 34 1e [2] 7a 12 [2] 76 18 [2] 61 13 [2] 7a 5d [2] 47 }

  condition:
    any of them
}