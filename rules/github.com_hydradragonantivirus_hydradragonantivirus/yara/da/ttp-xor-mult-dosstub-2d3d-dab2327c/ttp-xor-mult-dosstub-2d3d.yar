rule TTP_XOR_MULT_DOSStub_2d3d {
  strings:
    $key_2d3d = { 79 55 [2] 0d 4d [2] 4a 4f [2] 0d 5e [2] 43 52 [2] 4f 58 [2] 58 53 [2] 43 1d [2] 7e }

  condition:
    any of them
}