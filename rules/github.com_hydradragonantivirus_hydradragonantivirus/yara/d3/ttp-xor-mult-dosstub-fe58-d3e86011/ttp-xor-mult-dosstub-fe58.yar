rule TTP_XOR_MULT_DOSStub_fe58 {
  strings:
    $key_fe58 = { aa 30 [2] de 28 [2] 99 2a [2] de 3b [2] 90 37 [2] 9c 3d [2] 8b 36 [2] 90 78 [2] ad }

  condition:
    any of them
}