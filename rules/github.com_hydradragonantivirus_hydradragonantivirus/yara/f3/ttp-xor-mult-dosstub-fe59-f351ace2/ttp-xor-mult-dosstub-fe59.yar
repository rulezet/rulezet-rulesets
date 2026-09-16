rule TTP_XOR_MULT_DOSStub_fe59 {
  strings:
    $key_fe59 = { aa 31 [2] de 29 [2] 99 2b [2] de 3a [2] 90 36 [2] 9c 3c [2] 8b 37 [2] 90 79 [2] ad }

  condition:
    any of them
}