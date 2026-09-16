rule TTP_XOR_MULT_DOSStub_6879 {
  strings:
    $key_6879 = { 3c 11 [2] 48 09 [2] 0f 0b [2] 48 1a [2] 06 16 [2] 0a 1c [2] 1d 17 [2] 06 59 [2] 3b }

  condition:
    any of them
}