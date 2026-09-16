rule TTP_XOR_MULT_DOSStub_595d {
  strings:
    $key_595d = { 0d 35 [2] 79 2d [2] 3e 2f [2] 79 3e [2] 37 32 [2] 3b 38 [2] 2c 33 [2] 37 7d [2] 0a }

  condition:
    any of them
}