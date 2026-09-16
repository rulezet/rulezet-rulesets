rule TTP_XOR_MULT_DOSStub_3f4f {
  strings:
    $key_3f4f = { 6b 27 [2] 1f 3f [2] 58 3d [2] 1f 2c [2] 51 20 [2] 5d 2a [2] 4a 21 [2] 51 6f [2] 6c }

  condition:
    any of them
}