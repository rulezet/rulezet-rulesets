rule TTP_XOR_MULT_DOSStub_6304 {
  strings:
    $key_6304 = { 37 6c [2] 43 74 [2] 04 76 [2] 43 67 [2] 0d 6b [2] 01 61 [2] 16 6a [2] 0d 24 [2] 30 }

  condition:
    any of them
}