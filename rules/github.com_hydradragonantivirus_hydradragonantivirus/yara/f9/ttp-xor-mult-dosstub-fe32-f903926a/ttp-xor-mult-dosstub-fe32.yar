rule TTP_XOR_MULT_DOSStub_fe32 {
  strings:
    $key_fe32 = { aa 5a [2] de 42 [2] 99 40 [2] de 51 [2] 90 5d [2] 9c 57 [2] 8b 5c [2] 90 12 [2] ad }

  condition:
    any of them
}