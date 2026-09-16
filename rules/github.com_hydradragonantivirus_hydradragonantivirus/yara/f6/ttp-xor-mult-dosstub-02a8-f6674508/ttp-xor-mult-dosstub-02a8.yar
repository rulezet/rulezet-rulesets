rule TTP_XOR_MULT_DOSStub_02a8 {
  strings:
    $key_02a8 = { 56 c0 [2] 22 d8 [2] 65 da [2] 22 cb [2] 6c c7 [2] 60 cd [2] 77 c6 [2] 6c 88 [2] 51 }

  condition:
    any of them
}