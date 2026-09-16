rule TTP_XOR_MULT_DOSStub_fe6e {
  strings:
    $key_fe6e = { aa 06 [2] de 1e [2] 99 1c [2] de 0d [2] 90 01 [2] 9c 0b [2] 8b 00 [2] 90 4e [2] ad }

  condition:
    any of them
}