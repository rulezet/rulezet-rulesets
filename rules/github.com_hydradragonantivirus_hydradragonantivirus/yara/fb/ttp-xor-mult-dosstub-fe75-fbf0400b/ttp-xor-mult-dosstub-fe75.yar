rule TTP_XOR_MULT_DOSStub_fe75 {
  strings:
    $key_fe75 = { aa 1d [2] de 05 [2] 99 07 [2] de 16 [2] 90 1a [2] 9c 10 [2] 8b 1b [2] 90 55 [2] ad }

  condition:
    any of them
}