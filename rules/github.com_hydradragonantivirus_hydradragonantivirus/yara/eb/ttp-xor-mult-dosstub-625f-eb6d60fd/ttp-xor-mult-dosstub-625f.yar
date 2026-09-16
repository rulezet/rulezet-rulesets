rule TTP_XOR_MULT_DOSStub_625f {
  strings:
    $key_625f = { 36 37 [2] 42 2f [2] 05 2d [2] 42 3c [2] 0c 30 [2] 00 3a [2] 17 31 [2] 0c 7f [2] 31 }

  condition:
    any of them
}