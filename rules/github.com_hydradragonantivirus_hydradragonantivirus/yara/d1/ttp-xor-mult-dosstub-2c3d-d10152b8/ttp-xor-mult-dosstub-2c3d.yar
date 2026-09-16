rule TTP_XOR_MULT_DOSStub_2c3d {
  strings:
    $key_2c3d = { 78 55 [2] 0c 4d [2] 4b 4f [2] 0c 5e [2] 42 52 [2] 4e 58 [2] 59 53 [2] 42 1d [2] 7f }

  condition:
    any of them
}