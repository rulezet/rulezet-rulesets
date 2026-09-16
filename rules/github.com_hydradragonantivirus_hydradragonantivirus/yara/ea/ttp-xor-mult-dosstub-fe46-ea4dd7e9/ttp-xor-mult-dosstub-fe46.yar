rule TTP_XOR_MULT_DOSStub_fe46 {
  strings:
    $key_fe46 = { aa 2e [2] de 36 [2] 99 34 [2] de 25 [2] 90 29 [2] 9c 23 [2] 8b 28 [2] 90 66 [2] ad }

  condition:
    any of them
}