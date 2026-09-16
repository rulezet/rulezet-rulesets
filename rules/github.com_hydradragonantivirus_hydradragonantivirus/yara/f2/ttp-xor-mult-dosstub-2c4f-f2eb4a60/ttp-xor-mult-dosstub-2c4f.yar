rule TTP_XOR_MULT_DOSStub_2c4f {
  strings:
    $key_2c4f = { 78 27 [2] 0c 3f [2] 4b 3d [2] 0c 2c [2] 42 20 [2] 4e 2a [2] 59 21 [2] 42 6f [2] 7f }

  condition:
    any of them
}