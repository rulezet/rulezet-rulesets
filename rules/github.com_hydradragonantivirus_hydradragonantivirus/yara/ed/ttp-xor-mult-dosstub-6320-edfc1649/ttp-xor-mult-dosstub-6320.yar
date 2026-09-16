rule TTP_XOR_MULT_DOSStub_6320 {
  strings:
    $key_6320 = { 37 48 [2] 43 50 [2] 04 52 [2] 43 43 [2] 0d 4f [2] 01 45 [2] 16 4e [2] 0d 00 [2] 30 }

  condition:
    any of them
}