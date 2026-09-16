rule TTP_XOR_MULT_DOSStub_55f5 {
  strings:
    $key_55f5 = { 01 9d [2] 75 85 [2] 32 87 [2] 75 96 [2] 3b 9a [2] 37 90 [2] 20 9b [2] 3b d5 [2] 06 }

  condition:
    any of them
}