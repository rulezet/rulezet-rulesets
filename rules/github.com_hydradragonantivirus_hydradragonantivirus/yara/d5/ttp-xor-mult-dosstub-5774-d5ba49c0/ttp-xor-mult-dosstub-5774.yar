rule TTP_XOR_MULT_DOSStub_5774 {
  strings:
    $key_5774 = { 03 1c [2] 77 04 [2] 30 06 [2] 77 17 [2] 39 1b [2] 35 11 [2] 22 1a [2] 39 54 [2] 04 }

  condition:
    any of them
}