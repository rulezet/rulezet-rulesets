rule TTP_XOR_MULT_DOSStub_05e4 {
  strings:
    $key_05e4 = { 51 8c [2] 25 94 [2] 62 96 [2] 25 87 [2] 6b 8b [2] 67 81 [2] 70 8a [2] 6b c4 [2] 56 }

  condition:
    any of them
}