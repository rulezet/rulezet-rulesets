rule TTP_XOR_MULT_DOSStub_5074 {
  strings:
    $key_5074 = { 04 1c [2] 70 04 [2] 37 06 [2] 70 17 [2] 3e 1b [2] 32 11 [2] 25 1a [2] 3e 54 [2] 03 }

  condition:
    any of them
}