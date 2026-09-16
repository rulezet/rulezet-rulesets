rule TTP_XOR_MULT_DOSStub_6812 {
  strings:
    $key_6812 = { 3c 7a [2] 48 62 [2] 0f 60 [2] 48 71 [2] 06 7d [2] 0a 77 [2] 1d 7c [2] 06 32 [2] 3b }

  condition:
    any of them
}