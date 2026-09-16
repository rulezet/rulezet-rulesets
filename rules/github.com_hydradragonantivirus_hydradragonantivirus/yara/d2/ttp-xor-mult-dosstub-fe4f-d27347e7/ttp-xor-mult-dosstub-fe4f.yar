rule TTP_XOR_MULT_DOSStub_fe4f {
  strings:
    $key_fe4f = { aa 27 [2] de 3f [2] 99 3d [2] de 2c [2] 90 20 [2] 9c 2a [2] 8b 21 [2] 90 6f [2] ad }

  condition:
    any of them
}