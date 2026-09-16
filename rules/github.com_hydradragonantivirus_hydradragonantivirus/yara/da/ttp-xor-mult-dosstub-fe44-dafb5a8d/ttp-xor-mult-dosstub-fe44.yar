rule TTP_XOR_MULT_DOSStub_fe44 {
  strings:
    $key_fe44 = { aa 2c [2] de 34 [2] 99 36 [2] de 27 [2] 90 2b [2] 9c 21 [2] 8b 2a [2] 90 64 [2] ad }

  condition:
    any of them
}