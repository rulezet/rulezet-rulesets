rule TTP_XOR_MULT_DOSStub_fe6f {
  strings:
    $key_fe6f = { aa 07 [2] de 1f [2] 99 1d [2] de 0c [2] 90 00 [2] 9c 0a [2] 8b 01 [2] 90 4f [2] ad }

  condition:
    any of them
}