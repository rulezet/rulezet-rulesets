rule TTP_XOR_MULT_DOSStub_fe01 {
  strings:
    $key_fe01 = { aa 69 [2] de 71 [2] 99 73 [2] de 62 [2] 90 6e [2] 9c 64 [2] 8b 6f [2] 90 21 [2] ad }

  condition:
    any of them
}