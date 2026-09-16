rule TTP_XOR_MULT_DOSStub_20a8 {
  strings:
    $key_20a8 = { 74 c0 [2] 00 d8 [2] 47 da [2] 00 cb [2] 4e c7 [2] 42 cd [2] 55 c6 [2] 4e 88 [2] 73 }

  condition:
    any of them
}