rule TTP_XOR_MULT_DOSStub_1c3d {
  strings:
    $key_1c3d = { 48 55 [2] 3c 4d [2] 7b 4f [2] 3c 5e [2] 72 52 [2] 7e 58 [2] 69 53 [2] 72 1d [2] 4f }

  condition:
    any of them
}