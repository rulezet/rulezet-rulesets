rule TTP_XOR_MULT_DOSStub_1164 {
  strings:
    $key_1164 = { 45 0c [2] 31 14 [2] 76 16 [2] 31 07 [2] 7f 0b [2] 73 01 [2] 64 0a [2] 7f 44 [2] 42 }

  condition:
    any of them
}