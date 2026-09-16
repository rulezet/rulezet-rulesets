rule TTP_XOR_MULT_DOSStub_4779 {
  strings:
    $key_4779 = { 13 11 [2] 67 09 [2] 20 0b [2] 67 1a [2] 29 16 [2] 25 1c [2] 32 17 [2] 29 59 [2] 14 }

  condition:
    any of them
}