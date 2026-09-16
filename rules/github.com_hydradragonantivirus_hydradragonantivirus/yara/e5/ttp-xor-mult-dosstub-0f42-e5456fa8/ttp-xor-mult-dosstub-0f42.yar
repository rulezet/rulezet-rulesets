rule TTP_XOR_MULT_DOSStub_0f42 {
  strings:
    $key_0f42 = { 5b 2a [2] 2f 32 [2] 68 30 [2] 2f 21 [2] 61 2d [2] 6d 27 [2] 7a 2c [2] 61 62 [2] 5c }

  condition:
    any of them
}