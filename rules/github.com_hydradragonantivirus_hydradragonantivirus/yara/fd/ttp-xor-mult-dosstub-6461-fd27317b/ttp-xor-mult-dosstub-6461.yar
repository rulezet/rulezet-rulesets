rule TTP_XOR_MULT_DOSStub_6461 {
  strings:
    $key_6461 = { 30 09 [2] 44 11 [2] 03 13 [2] 44 02 [2] 0a 0e [2] 06 04 [2] 11 0f [2] 0a 41 [2] 37 }

  condition:
    any of them
}