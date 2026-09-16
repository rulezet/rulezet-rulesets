rule TTP_XOR_MULT_DOSStub_fe25 {
  strings:
    $key_fe25 = { aa 4d [2] de 55 [2] 99 57 [2] de 46 [2] 90 4a [2] 9c 40 [2] 8b 4b [2] 90 05 [2] ad }

  condition:
    any of them
}