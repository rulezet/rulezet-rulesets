rule TTP_XOR_MULT_DOSStub_6110 {
  strings:
    $key_6110 = { 35 78 [2] 41 60 [2] 06 62 [2] 41 73 [2] 0f 7f [2] 03 75 [2] 14 7e [2] 0f 30 [2] 32 }

  condition:
    any of them
}