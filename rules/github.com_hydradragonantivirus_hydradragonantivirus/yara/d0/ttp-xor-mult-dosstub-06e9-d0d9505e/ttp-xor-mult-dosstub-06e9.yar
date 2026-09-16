rule TTP_XOR_MULT_DOSStub_06e9 {
  strings:
    $key_06e9 = { 52 81 [2] 26 99 [2] 61 9b [2] 26 8a [2] 68 86 [2] 64 8c [2] 73 87 [2] 68 c9 [2] 55 }

  condition:
    any of them
}