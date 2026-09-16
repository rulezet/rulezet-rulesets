rule TTP_XOR_MULT_DOSStub_fe05 {
  strings:
    $key_fe05 = { aa 6d [2] de 75 [2] 99 77 [2] de 66 [2] 90 6a [2] 9c 60 [2] 8b 6b [2] 90 25 [2] ad }

  condition:
    any of them
}