rule TTP_XOR_MULT_DOSStub_4b3d {
  strings:
    $key_4b3d = { 1f 55 [2] 6b 4d [2] 2c 4f [2] 6b 5e [2] 25 52 [2] 29 58 [2] 3e 53 [2] 25 1d [2] 18 }

  condition:
    any of them
}