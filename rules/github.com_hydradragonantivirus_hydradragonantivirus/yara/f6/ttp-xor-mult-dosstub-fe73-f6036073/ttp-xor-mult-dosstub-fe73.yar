rule TTP_XOR_MULT_DOSStub_fe73 {
  strings:
    $key_fe73 = { aa 1b [2] de 03 [2] 99 01 [2] de 10 [2] 90 1c [2] 9c 16 [2] 8b 1d [2] 90 53 [2] ad }

  condition:
    any of them
}