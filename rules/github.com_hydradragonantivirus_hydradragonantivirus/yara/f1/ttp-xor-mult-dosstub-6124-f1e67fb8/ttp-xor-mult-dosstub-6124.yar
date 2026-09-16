rule TTP_XOR_MULT_DOSStub_6124 {
  strings:
    $key_6124 = { 35 4c [2] 41 54 [2] 06 56 [2] 41 47 [2] 0f 4b [2] 03 41 [2] 14 4a [2] 0f 04 [2] 32 }

  condition:
    any of them
}