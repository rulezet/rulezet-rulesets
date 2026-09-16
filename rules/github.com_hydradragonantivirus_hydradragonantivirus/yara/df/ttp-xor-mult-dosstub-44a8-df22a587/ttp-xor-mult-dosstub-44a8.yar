rule TTP_XOR_MULT_DOSStub_44a8 {
  strings:
    $key_44a8 = { 10 c0 [2] 64 d8 [2] 23 da [2] 64 cb [2] 2a c7 [2] 26 cd [2] 31 c6 [2] 2a 88 [2] 17 }

  condition:
    any of them
}