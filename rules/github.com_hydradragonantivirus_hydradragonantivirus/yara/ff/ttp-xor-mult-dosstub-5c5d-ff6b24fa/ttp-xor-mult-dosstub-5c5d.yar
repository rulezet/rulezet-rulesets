rule TTP_XOR_MULT_DOSStub_5c5d {
  strings:
    $key_5c5d = { 08 35 [2] 7c 2d [2] 3b 2f [2] 7c 3e [2] 32 32 [2] 3e 38 [2] 29 33 [2] 32 7d [2] 0f }

  condition:
    any of them
}