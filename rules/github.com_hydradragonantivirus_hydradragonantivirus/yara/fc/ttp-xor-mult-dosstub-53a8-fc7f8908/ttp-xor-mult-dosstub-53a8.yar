rule TTP_XOR_MULT_DOSStub_53a8 {
  strings:
    $key_53a8 = { 07 c0 [2] 73 d8 [2] 34 da [2] 73 cb [2] 3d c7 [2] 31 cd [2] 26 c6 [2] 3d 88 [2] 00 }

  condition:
    any of them
}