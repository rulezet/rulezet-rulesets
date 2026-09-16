rule TTP_XOR_MULT_DOSStub_3b44 {
  strings:
    $key_3b44 = { 6f 2c [2] 1b 34 [2] 5c 36 [2] 1b 27 [2] 55 2b [2] 59 21 [2] 4e 2a [2] 55 64 [2] 68 }

  condition:
    any of them
}