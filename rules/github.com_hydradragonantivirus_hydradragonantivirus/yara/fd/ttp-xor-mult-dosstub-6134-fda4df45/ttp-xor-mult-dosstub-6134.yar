rule TTP_XOR_MULT_DOSStub_6134 {
  strings:
    $key_6134 = { 35 5c [2] 41 44 [2] 06 46 [2] 41 57 [2] 0f 5b [2] 03 51 [2] 14 5a [2] 0f 14 [2] 32 }

  condition:
    any of them
}