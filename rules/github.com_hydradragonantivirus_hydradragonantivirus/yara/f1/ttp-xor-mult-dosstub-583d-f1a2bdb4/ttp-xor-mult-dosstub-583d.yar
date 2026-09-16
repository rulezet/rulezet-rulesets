rule TTP_XOR_MULT_DOSStub_583d {
  strings:
    $key_583d = { 0c 55 [2] 78 4d [2] 3f 4f [2] 78 5e [2] 36 52 [2] 3a 58 [2] 2d 53 [2] 36 1d [2] 0b }

  condition:
    any of them
}