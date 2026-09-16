rule TTP_XOR_MULT_DOSStub_05e9 {
  strings:
    $key_05e9 = { 51 81 [2] 25 99 [2] 62 9b [2] 25 8a [2] 6b 86 [2] 67 8c [2] 70 87 [2] 6b c9 [2] 56 }

  condition:
    any of them
}