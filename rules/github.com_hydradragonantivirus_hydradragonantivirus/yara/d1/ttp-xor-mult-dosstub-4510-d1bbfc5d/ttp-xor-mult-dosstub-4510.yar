rule TTP_XOR_MULT_DOSStub_4510 {
  strings:
    $key_4510 = { 11 78 [2] 65 60 [2] 22 62 [2] 65 73 [2] 2b 7f [2] 27 75 [2] 30 7e [2] 2b 30 [2] 16 }

  condition:
    any of them
}