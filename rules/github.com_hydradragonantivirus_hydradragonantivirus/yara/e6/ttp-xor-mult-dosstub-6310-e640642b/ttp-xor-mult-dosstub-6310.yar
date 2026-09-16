rule TTP_XOR_MULT_DOSStub_6310 {
  strings:
    $key_6310 = { 37 78 [2] 43 60 [2] 04 62 [2] 43 73 [2] 0d 7f [2] 01 75 [2] 16 7e [2] 0d 30 [2] 30 }

  condition:
    any of them
}