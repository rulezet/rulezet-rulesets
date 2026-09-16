rule TTP_XOR_MULT_DOSStub_3574 {
  strings:
    $key_3574 = { 61 1c [2] 15 04 [2] 52 06 [2] 15 17 [2] 5b 1b [2] 57 11 [2] 40 1a [2] 5b 54 [2] 66 }

  condition:
    any of them
}