rule TTP_XOR_MULT_DOSStub_fe7c {
  strings:
    $key_fe7c = { aa 14 [2] de 0c [2] 99 0e [2] de 1f [2] 90 13 [2] 9c 19 [2] 8b 12 [2] 90 5c [2] ad }

  condition:
    any of them
}