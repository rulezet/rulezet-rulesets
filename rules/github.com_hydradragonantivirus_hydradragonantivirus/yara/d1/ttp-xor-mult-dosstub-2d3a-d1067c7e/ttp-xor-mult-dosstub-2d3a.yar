rule TTP_XOR_MULT_DOSStub_2d3a {
  strings:
    $key_2d3a = { 79 52 [2] 0d 4a [2] 4a 48 [2] 0d 59 [2] 43 55 [2] 4f 5f [2] 58 54 [2] 43 1a [2] 7e }

  condition:
    any of them
}