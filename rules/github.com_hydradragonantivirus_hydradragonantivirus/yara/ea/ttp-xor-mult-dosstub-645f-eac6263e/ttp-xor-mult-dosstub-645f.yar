rule TTP_XOR_MULT_DOSStub_645f {
  strings:
    $key_645f = { 30 37 [2] 44 2f [2] 03 2d [2] 44 3c [2] 0a 30 [2] 06 3a [2] 11 31 [2] 0a 7f [2] 37 }

  condition:
    any of them
}