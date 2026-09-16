rule TTP_XOR_MULT_DOSStub_784a {
  strings:
    $key_784a = { 2c 22 [2] 58 3a [2] 1f 38 [2] 58 29 [2] 16 25 [2] 1a 2f [2] 0d 24 [2] 16 6a [2] 2b }

  condition:
    any of them
}