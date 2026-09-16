rule TTP_XOR_MULT_DOSStub_fe2d {
  strings:
    $key_fe2d = { aa 45 [2] de 5d [2] 99 5f [2] de 4e [2] 90 42 [2] 9c 48 [2] 8b 43 [2] 90 0d [2] ad }

  condition:
    any of them
}