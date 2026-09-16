rule TTP_XOR_MULT_DOSStub_fe0b {
  strings:
    $key_fe0b = { aa 63 [2] de 7b [2] 99 79 [2] de 68 [2] 90 64 [2] 9c 6e [2] 8b 65 [2] 90 2b [2] ad }

  condition:
    any of them
}