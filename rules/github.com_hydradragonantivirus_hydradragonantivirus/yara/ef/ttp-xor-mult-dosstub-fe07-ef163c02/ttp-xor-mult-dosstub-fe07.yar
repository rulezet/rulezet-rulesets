rule TTP_XOR_MULT_DOSStub_fe07 {
  strings:
    $key_fe07 = { aa 6f [2] de 77 [2] 99 75 [2] de 64 [2] 90 68 [2] 9c 62 [2] 8b 69 [2] 90 27 [2] ad }

  condition:
    any of them
}