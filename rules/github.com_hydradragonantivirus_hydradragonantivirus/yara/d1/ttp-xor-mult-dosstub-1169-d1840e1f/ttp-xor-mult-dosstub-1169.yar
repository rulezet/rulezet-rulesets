rule TTP_XOR_MULT_DOSStub_1169 {
  strings:
    $key_1169 = { 45 01 [2] 31 19 [2] 76 1b [2] 31 0a [2] 7f 06 [2] 73 0c [2] 64 07 [2] 7f 49 [2] 42 }

  condition:
    any of them
}