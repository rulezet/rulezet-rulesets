rule TTP_XOR_MULT_DOSStub_5f4f {
  strings:
    $key_5f4f = { 0b 27 [2] 7f 3f [2] 38 3d [2] 7f 2c [2] 31 20 [2] 3d 2a [2] 2a 21 [2] 31 6f [2] 0c }

  condition:
    any of them
}