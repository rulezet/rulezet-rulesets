rule TTP_XOR_MULT_DOSStub_7f3d {
  strings:
    $key_7f3d = { 2b 55 [2] 5f 4d [2] 18 4f [2] 5f 5e [2] 11 52 [2] 1d 58 [2] 0a 53 [2] 11 1d [2] 2c }

  condition:
    any of them
}