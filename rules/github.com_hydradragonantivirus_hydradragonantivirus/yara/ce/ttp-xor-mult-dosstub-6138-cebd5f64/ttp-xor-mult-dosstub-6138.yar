rule TTP_XOR_MULT_DOSStub_6138 {
  strings:
    $key_6138 = { 35 50 [2] 41 48 [2] 06 4a [2] 41 5b [2] 0f 57 [2] 03 5d [2] 14 56 [2] 0f 18 [2] 32 }

  condition:
    any of them
}