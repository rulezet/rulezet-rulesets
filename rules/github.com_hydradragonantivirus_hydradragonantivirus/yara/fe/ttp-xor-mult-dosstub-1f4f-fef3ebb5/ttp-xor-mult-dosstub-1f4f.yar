rule TTP_XOR_MULT_DOSStub_1f4f {
  strings:
    $key_1f4f = { 4b 27 [2] 3f 3f [2] 78 3d [2] 3f 2c [2] 71 20 [2] 7d 2a [2] 6a 21 [2] 71 6f [2] 4c }

  condition:
    any of them
}