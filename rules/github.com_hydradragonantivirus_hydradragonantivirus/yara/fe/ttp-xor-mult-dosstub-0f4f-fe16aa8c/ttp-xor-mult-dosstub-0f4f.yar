rule TTP_XOR_MULT_DOSStub_0f4f {
  strings:
    $key_0f4f = { 5b 27 [2] 2f 3f [2] 68 3d [2] 2f 2c [2] 61 20 [2] 6d 2a [2] 7a 21 [2] 61 6f [2] 5c }

  condition:
    any of them
}