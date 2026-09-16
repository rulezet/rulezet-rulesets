rule TTP_XOR_MULT_DOSStub_73a8 {
  strings:
    $key_73a8 = { 27 c0 [2] 53 d8 [2] 14 da [2] 53 cb [2] 1d c7 [2] 11 cd [2] 06 c6 [2] 1d 88 [2] 20 }

  condition:
    any of them
}