rule TTP_XOR_MULT_DOSStub_66e4 {
  strings:
    $key_66e4 = { 32 8c [2] 46 94 [2] 01 96 [2] 46 87 [2] 08 8b [2] 04 81 [2] 13 8a [2] 08 c4 [2] 35 }

  condition:
    any of them
}