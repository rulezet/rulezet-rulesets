rule TTP_XOR_MULT_DOSStub_65e9 {
  strings:
    $key_65e9 = { 31 81 [2] 45 99 [2] 02 9b [2] 45 8a [2] 0b 86 [2] 07 8c [2] 10 87 [2] 0b c9 [2] 36 }

  condition:
    any of them
}