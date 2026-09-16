rule TTP_XOR_MULT_DOSStub_fe08 {
  strings:
    $key_fe08 = { aa 60 [2] de 78 [2] 99 7a [2] de 6b [2] 90 67 [2] 9c 6d [2] 8b 66 [2] 90 28 [2] ad }

  condition:
    any of them
}