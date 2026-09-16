rule TTP_XOR_MULT_DOSStub_6125 {
  strings:
    $key_6125 = { 35 4d [2] 41 55 [2] 06 57 [2] 41 46 [2] 0f 4a [2] 03 40 [2] 14 4b [2] 0f 05 [2] 32 }

  condition:
    any of them
}