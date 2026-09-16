rule TTP_XOR_MULT_DOSStub_fe36 {
  strings:
    $key_fe36 = { aa 5e [2] de 46 [2] 99 44 [2] de 55 [2] 90 59 [2] 9c 53 [2] 8b 58 [2] 90 16 [2] ad }

  condition:
    any of them
}