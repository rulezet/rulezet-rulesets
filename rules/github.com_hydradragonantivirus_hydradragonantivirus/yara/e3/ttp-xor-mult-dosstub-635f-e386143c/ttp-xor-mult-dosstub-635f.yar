rule TTP_XOR_MULT_DOSStub_635f {
  strings:
    $key_635f = { 37 37 [2] 43 2f [2] 04 2d [2] 43 3c [2] 0d 30 [2] 01 3a [2] 16 31 [2] 0d 7f [2] 30 }

  condition:
    any of them
}