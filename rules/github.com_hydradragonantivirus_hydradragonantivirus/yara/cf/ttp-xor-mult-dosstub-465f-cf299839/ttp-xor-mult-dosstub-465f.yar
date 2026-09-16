rule TTP_XOR_MULT_DOSStub_465f {
  strings:
    $key_465f = { 12 37 [2] 66 2f [2] 21 2d [2] 66 3c [2] 28 30 [2] 24 3a [2] 33 31 [2] 28 7f [2] 15 }

  condition:
    any of them
}