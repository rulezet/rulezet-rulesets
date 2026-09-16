rule TTP_XOR_MULT_DOSStub_5df5 {
  strings:
    $key_5df5 = { 09 9d [2] 7d 85 [2] 3a 87 [2] 7d 96 [2] 33 9a [2] 3f 90 [2] 28 9b [2] 33 d5 [2] 0e }

  condition:
    any of them
}