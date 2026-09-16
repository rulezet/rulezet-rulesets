rule TTP_XOR_MULT_DOSStub_2164 {
  strings:
    $key_2164 = { 75 0c [2] 01 14 [2] 46 16 [2] 01 07 [2] 4f 0b [2] 43 01 [2] 54 0a [2] 4f 44 [2] 72 }

  condition:
    any of them
}