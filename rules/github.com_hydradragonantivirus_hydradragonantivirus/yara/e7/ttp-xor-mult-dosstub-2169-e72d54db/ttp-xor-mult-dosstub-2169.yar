rule TTP_XOR_MULT_DOSStub_2169 {
  strings:
    $key_2169 = { 75 01 [2] 01 19 [2] 46 1b [2] 01 0a [2] 4f 06 [2] 43 0c [2] 54 07 [2] 4f 49 [2] 72 }

  condition:
    any of them
}