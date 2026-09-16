rule TTP_XOR_MULT_DOSStub_6a54 {
  strings:
    $key_6a54 = { 3e 3c [2] 4a 24 [2] 0d 26 [2] 4a 37 [2] 04 3b [2] 08 31 [2] 1f 3a [2] 04 74 [2] 39 }

  condition:
    any of them
}