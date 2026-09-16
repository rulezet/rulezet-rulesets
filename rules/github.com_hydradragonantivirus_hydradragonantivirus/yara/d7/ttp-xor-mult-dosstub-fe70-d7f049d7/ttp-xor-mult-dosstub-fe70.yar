rule TTP_XOR_MULT_DOSStub_fe70 {
  strings:
    $key_fe70 = { aa 18 [2] de 00 [2] 99 02 [2] de 13 [2] 90 1f [2] 9c 15 [2] 8b 1e [2] 90 50 [2] ad }

  condition:
    any of them
}