rule TTP_XOR_MULT_DOSStub_fe77 {
  strings:
    $key_fe77 = { aa 1f [2] de 07 [2] 99 05 [2] de 14 [2] 90 18 [2] 9c 12 [2] 8b 19 [2] 90 57 [2] ad }

  condition:
    any of them
}