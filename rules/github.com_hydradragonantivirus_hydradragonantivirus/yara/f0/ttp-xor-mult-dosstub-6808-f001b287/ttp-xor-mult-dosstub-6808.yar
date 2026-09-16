rule TTP_XOR_MULT_DOSStub_6808 {
  strings:
    $key_6808 = { 3c 60 [2] 48 78 [2] 0f 7a [2] 48 6b [2] 06 67 [2] 0a 6d [2] 1d 66 [2] 06 28 [2] 3b }

  condition:
    any of them
}