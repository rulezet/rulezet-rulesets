rule TTP_XOR_MULT_DOSStub_504f {
  strings:
    $key_504f = { 04 27 [2] 70 3f [2] 37 3d [2] 70 2c [2] 3e 20 [2] 32 2a [2] 25 21 [2] 3e 6f [2] 03 }

  condition:
    any of them
}