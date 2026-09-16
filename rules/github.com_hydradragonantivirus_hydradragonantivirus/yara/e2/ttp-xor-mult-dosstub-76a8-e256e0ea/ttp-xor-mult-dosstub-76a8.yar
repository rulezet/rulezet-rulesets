rule TTP_XOR_MULT_DOSStub_76a8 {
  strings:
    $key_76a8 = { 22 c0 [2] 56 d8 [2] 11 da [2] 56 cb [2] 18 c7 [2] 14 cd [2] 03 c6 [2] 18 88 [2] 25 }

  condition:
    any of them
}