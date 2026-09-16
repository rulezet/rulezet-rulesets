rule TTP_XOR_MULT_DOSStub_10a8 {
  strings:
    $key_10a8 = { 44 c0 [2] 30 d8 [2] 77 da [2] 30 cb [2] 7e c7 [2] 72 cd [2] 65 c6 [2] 7e 88 [2] 43 }

  condition:
    any of them
}