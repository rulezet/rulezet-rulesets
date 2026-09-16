rule TTP_XOR_MULT_DOSStub_fe3f {
  strings:
    $key_fe3f = { aa 57 [2] de 4f [2] 99 4d [2] de 5c [2] 90 50 [2] 9c 5a [2] 8b 51 [2] 90 1f [2] ad }

  condition:
    any of them
}