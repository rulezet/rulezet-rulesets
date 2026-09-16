rule TTP_XOR_MULT_DOSStub_fe2a {
  strings:
    $key_fe2a = { aa 42 [2] de 5a [2] 99 58 [2] de 49 [2] 90 45 [2] 9c 4f [2] 8b 44 [2] 90 0a [2] ad }

  condition:
    any of them
}