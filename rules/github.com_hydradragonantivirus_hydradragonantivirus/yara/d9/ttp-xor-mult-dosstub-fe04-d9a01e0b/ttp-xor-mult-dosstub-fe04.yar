rule TTP_XOR_MULT_DOSStub_fe04 {
  strings:
    $key_fe04 = { aa 6c [2] de 74 [2] 99 76 [2] de 67 [2] 90 6b [2] 9c 61 [2] 8b 6a [2] 90 24 [2] ad }

  condition:
    any of them
}