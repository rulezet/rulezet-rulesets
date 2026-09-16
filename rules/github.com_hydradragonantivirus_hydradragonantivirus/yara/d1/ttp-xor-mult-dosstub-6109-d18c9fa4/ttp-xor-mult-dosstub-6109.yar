rule TTP_XOR_MULT_DOSStub_6109 {
  strings:
    $key_6109 = { 35 61 [2] 41 79 [2] 06 7b [2] 41 6a [2] 0f 66 [2] 03 6c [2] 14 67 [2] 0f 29 [2] 32 }

  condition:
    any of them
}