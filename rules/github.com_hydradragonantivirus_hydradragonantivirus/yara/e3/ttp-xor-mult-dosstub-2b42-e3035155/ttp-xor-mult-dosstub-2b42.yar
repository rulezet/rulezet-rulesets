rule TTP_XOR_MULT_DOSStub_2b42 {
  strings:
    $key_2b42 = { 7f 2a [2] 0b 32 [2] 4c 30 [2] 0b 21 [2] 45 2d [2] 49 27 [2] 5e 2c [2] 45 62 [2] 78 }

  condition:
    any of them
}