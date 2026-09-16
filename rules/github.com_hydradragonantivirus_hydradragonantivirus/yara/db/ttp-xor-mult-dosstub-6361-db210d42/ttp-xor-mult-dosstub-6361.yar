rule TTP_XOR_MULT_DOSStub_6361 {
  strings:
    $key_6361 = { 37 09 [2] 43 11 [2] 04 13 [2] 43 02 [2] 0d 0e [2] 01 04 [2] 16 0f [2] 0d 41 [2] 30 }

  condition:
    any of them
}