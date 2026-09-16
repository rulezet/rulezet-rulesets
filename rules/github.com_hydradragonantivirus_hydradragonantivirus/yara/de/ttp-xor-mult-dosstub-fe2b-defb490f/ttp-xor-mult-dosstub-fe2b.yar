rule TTP_XOR_MULT_DOSStub_fe2b {
  strings:
    $key_fe2b = { aa 43 [2] de 5b [2] 99 59 [2] de 48 [2] 90 44 [2] 9c 4e [2] 8b 45 [2] 90 0b [2] ad }

  condition:
    any of them
}