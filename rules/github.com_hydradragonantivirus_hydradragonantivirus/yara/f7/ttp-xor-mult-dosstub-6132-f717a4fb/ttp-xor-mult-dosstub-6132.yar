rule TTP_XOR_MULT_DOSStub_6132 {
  strings:
    $key_6132 = { 35 5a [2] 41 42 [2] 06 40 [2] 41 51 [2] 0f 5d [2] 03 57 [2] 14 5c [2] 0f 12 [2] 32 }

  condition:
    any of them
}