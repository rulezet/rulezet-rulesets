rule TTP_XOR_MULT_DOSStub_fe35 {
  strings:
    $key_fe35 = { aa 5d [2] de 45 [2] 99 47 [2] de 56 [2] 90 5a [2] 9c 50 [2] 8b 5b [2] 90 15 [2] ad }

  condition:
    any of them
}