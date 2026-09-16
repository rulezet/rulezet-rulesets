rule TTP_XOR_MULT_DOSStub_075d {
  strings:
    $key_075d = { 53 35 [2] 27 2d [2] 60 2f [2] 27 3e [2] 69 32 [2] 65 38 [2] 72 33 [2] 69 7d [2] 54 }

  condition:
    any of them
}