rule TTP_XOR_MULT_DOSStub_fe09 {
  strings:
    $key_fe09 = { aa 61 [2] de 79 [2] 99 7b [2] de 6a [2] 90 66 [2] 9c 6c [2] 8b 67 [2] 90 29 [2] ad }

  condition:
    any of them
}