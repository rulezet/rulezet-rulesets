rule TTP_XOR_MULT_DOSStub_5742 {
  strings:
    $key_5742 = { 03 2a [2] 77 32 [2] 30 30 [2] 77 21 [2] 39 2d [2] 35 27 [2] 22 2c [2] 39 62 [2] 04 }

  condition:
    any of them
}