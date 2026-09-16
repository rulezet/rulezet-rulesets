rule TTP_XOR_MULT_DOSStub_68f5 {
  strings:
    $key_68f5 = { 3c 9d [2] 48 85 [2] 0f 87 [2] 48 96 [2] 06 9a [2] 0a 90 [2] 1d 9b [2] 06 d5 [2] 3b }

  condition:
    any of them
}