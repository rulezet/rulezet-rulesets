rule TTP_XOR_MULT_DOSStub_79a2 {
  strings:
    $key_79a2 = { 2d ca [2] 59 d2 [2] 1e d0 [2] 59 c1 [2] 17 cd [2] 1b c7 [2] 0c cc [2] 17 82 [2] 2a }

  condition:
    any of them
}