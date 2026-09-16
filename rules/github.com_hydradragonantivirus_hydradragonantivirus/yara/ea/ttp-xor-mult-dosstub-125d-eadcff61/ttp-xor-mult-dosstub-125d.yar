rule TTP_XOR_MULT_DOSStub_125d {
  strings:
    $key_125d = { 46 35 [2] 32 2d [2] 75 2f [2] 32 3e [2] 7c 32 [2] 70 38 [2] 67 33 [2] 7c 7d [2] 41 }

  condition:
    any of them
}