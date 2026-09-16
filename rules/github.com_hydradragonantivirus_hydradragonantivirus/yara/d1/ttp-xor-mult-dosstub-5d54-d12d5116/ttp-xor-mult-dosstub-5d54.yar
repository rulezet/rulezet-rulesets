rule TTP_XOR_MULT_DOSStub_5d54 {
  strings:
    $key_5d54 = { 09 3c [2] 7d 24 [2] 3a 26 [2] 7d 37 [2] 33 3b [2] 3f 31 [2] 28 3a [2] 33 74 [2] 0e }

  condition:
    any of them
}