rule TTP_XOR_MULT_DOSStub_fe50 {
  strings:
    $key_fe50 = { aa 38 [2] de 20 [2] 99 22 [2] de 33 [2] 90 3f [2] 9c 35 [2] 8b 3e [2] 90 70 [2] ad }

  condition:
    any of them
}