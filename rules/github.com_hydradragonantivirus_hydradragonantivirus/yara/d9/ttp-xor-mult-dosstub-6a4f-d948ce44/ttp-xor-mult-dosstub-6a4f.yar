rule TTP_XOR_MULT_DOSStub_6a4f {
  strings:
    $key_6a4f = { 3e 27 [2] 4a 3f [2] 0d 3d [2] 4a 2c [2] 04 20 [2] 08 2a [2] 1f 21 [2] 04 6f [2] 39 }

  condition:
    any of them
}