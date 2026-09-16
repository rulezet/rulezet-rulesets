rule TTP_XOR_MULT_DOSStub_72e9 {
  strings:
    $key_72e9 = { 26 81 [2] 52 99 [2] 15 9b [2] 52 8a [2] 1c 86 [2] 10 8c [2] 07 87 [2] 1c c9 [2] 21 }

  condition:
    any of them
}