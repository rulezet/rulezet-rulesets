rule TTP_XOR_MULT_DOSStub_6161 {
  strings:
    $key_6161 = { 35 09 [2] 41 11 [2] 06 13 [2] 41 02 [2] 0f 0e [2] 03 04 [2] 14 0f [2] 0f 41 [2] 32 }

  condition:
    any of them
}