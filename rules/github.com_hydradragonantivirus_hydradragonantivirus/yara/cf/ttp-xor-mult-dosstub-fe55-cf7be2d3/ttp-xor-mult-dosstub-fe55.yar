rule TTP_XOR_MULT_DOSStub_fe55 {
  strings:
    $key_fe55 = { aa 3d [2] de 25 [2] 99 27 [2] de 36 [2] 90 3a [2] 9c 30 [2] 8b 3b [2] 90 75 [2] ad }

  condition:
    any of them
}