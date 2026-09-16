rule TTP_XOR_MULT_DOSStub_fe78 {
  strings:
    $key_fe78 = { aa 10 [2] de 08 [2] 99 0a [2] de 1b [2] 90 17 [2] 9c 1d [2] 8b 16 [2] 90 58 [2] ad }

  condition:
    any of them
}