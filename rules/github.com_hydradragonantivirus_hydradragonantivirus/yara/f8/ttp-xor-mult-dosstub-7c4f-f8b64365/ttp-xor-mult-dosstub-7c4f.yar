rule TTP_XOR_MULT_DOSStub_7c4f {
  strings:
    $key_7c4f = { 28 27 [2] 5c 3f [2] 1b 3d [2] 5c 2c [2] 12 20 [2] 1e 2a [2] 09 21 [2] 12 6f [2] 2f }

  condition:
    any of them
}