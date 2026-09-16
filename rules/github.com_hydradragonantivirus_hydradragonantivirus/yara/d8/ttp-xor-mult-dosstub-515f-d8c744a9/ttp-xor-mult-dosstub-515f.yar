rule TTP_XOR_MULT_DOSStub_515f {
  strings:
    $key_515f = { 05 37 [2] 71 2f [2] 36 2d [2] 71 3c [2] 3f 30 [2] 33 3a [2] 24 31 [2] 3f 7f [2] 02 }

  condition:
    any of them
}