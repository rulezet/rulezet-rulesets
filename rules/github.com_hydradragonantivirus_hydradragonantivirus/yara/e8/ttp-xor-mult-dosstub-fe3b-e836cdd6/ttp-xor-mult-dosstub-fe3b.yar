rule TTP_XOR_MULT_DOSStub_fe3b {
  strings:
    $key_fe3b = { aa 53 [2] de 4b [2] 99 49 [2] de 58 [2] 90 54 [2] 9c 5e [2] 8b 55 [2] 90 1b [2] ad }

  condition:
    any of them
}