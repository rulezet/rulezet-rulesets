rule TTP_XOR_MULT_DOSStub_12a8 {
  strings:
    $key_12a8 = { 46 c0 [2] 32 d8 [2] 75 da [2] 32 cb [2] 7c c7 [2] 70 cd [2] 67 c6 [2] 7c 88 [2] 41 }

  condition:
    any of them
}