rule TTP_XOR_MULT_DOSStub_05a8 {
  strings:
    $key_05a8 = { 51 c0 [2] 25 d8 [2] 62 da [2] 25 cb [2] 6b c7 [2] 67 cd [2] 70 c6 [2] 6b 88 [2] 56 }

  condition:
    any of them
}