rule TTP_XOR_MULT_DOSStub_7245 {
  strings:
    $key_7245 = { 26 2d [2] 52 35 [2] 15 37 [2] 52 26 [2] 1c 2a [2] 10 20 [2] 07 2b [2] 1c 65 [2] 21 }

  condition:
    any of them
}