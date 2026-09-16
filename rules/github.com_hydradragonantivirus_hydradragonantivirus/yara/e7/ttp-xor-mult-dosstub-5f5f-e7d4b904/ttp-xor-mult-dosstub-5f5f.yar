rule TTP_XOR_MULT_DOSStub_5f5f {
  strings:
    $key_5f5f = { 0b 37 [2] 7f 2f [2] 38 2d [2] 7f 3c [2] 31 30 [2] 3d 3a [2] 2a 31 [2] 31 7f [2] 0c }

  condition:
    any of them
}