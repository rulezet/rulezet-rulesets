rule TTP_XOR_MULT_DOSStub_fe0f {
  strings:
    $key_fe0f = { aa 67 [2] de 7f [2] 99 7d [2] de 6c [2] 90 60 [2] 9c 6a [2] 8b 61 [2] 90 2f [2] ad }

  condition:
    any of them
}