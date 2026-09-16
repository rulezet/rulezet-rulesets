rule TTP_XOR_MULT_DOSStub_2c5d {
  strings:
    $key_2c5d = { 78 35 [2] 0c 2d [2] 4b 2f [2] 0c 3e [2] 42 32 [2] 4e 38 [2] 59 33 [2] 42 7d [2] 7f }

  condition:
    any of them
}