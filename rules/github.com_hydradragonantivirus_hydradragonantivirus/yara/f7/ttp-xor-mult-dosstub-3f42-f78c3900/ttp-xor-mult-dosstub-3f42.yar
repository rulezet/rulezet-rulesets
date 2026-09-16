rule TTP_XOR_MULT_DOSStub_3f42 {
  strings:
    $key_3f42 = { 6b 2a [2] 1f 32 [2] 58 30 [2] 1f 21 [2] 51 2d [2] 5d 27 [2] 4a 2c [2] 51 62 [2] 6c }

  condition:
    any of them
}