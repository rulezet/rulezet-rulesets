rule TTP_XOR_MULT_DOSStub_0dda {
  strings:
    $key_0dda = { 59 b2 [2] 2d aa [2] 6a a8 [2] 2d b9 [2] 63 b5 [2] 6f bf [2] 78 b4 [2] 63 fa [2] 5e }

  condition:
    any of them
}