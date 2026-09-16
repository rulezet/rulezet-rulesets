rule TTP_XOR_MULT_DOSStub_5175 {
  strings:
    $key_5175 = { 05 1d [2] 71 05 [2] 36 07 [2] 71 16 [2] 3f 1a [2] 33 10 [2] 24 1b [2] 3f 55 [2] 02 }

  condition:
    any of them
}