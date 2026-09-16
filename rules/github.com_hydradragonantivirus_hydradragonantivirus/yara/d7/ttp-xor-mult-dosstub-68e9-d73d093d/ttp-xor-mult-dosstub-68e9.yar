rule TTP_XOR_MULT_DOSStub_68e9 {
  strings:
    $key_68e9 = { 3c 81 [2] 48 99 [2] 0f 9b [2] 48 8a [2] 06 86 [2] 0a 8c [2] 1d 87 [2] 06 c9 [2] 3b }

  condition:
    any of them
}