rule TTP_XOR_MULT_DOSStub_364f {
  strings:
    $key_364f = { 62 27 [2] 16 3f [2] 51 3d [2] 16 2c [2] 58 20 [2] 54 2a [2] 43 21 [2] 58 6f [2] 65 }

  condition:
    any of them
}