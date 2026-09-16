rule TTP_XOR_MULT_DOSStub_6f4f {
  strings:
    $key_6f4f = { 3b 27 [2] 4f 3f [2] 08 3d [2] 4f 2c [2] 01 20 [2] 0d 2a [2] 1a 21 [2] 01 6f [2] 3c }

  condition:
    any of them
}