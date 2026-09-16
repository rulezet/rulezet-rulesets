rule TTP_XOR_MULT_DOSStub_075f {
  strings:
    $key_075f = { 53 37 [2] 27 2f [2] 60 2d [2] 27 3c [2] 69 30 [2] 65 3a [2] 72 31 [2] 69 7f [2] 54 }

  condition:
    any of them
}