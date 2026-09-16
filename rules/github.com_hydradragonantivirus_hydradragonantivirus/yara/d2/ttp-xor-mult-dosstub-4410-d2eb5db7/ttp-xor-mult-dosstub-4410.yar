rule TTP_XOR_MULT_DOSStub_4410 {
  strings:
    $key_4410 = { 10 78 [2] 64 60 [2] 23 62 [2] 64 73 [2] 2a 7f [2] 26 75 [2] 31 7e [2] 2a 30 [2] 17 }

  condition:
    any of them
}