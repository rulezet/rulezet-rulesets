rule TTP_XOR_MULT_DOSStub_e4a8 {
  strings:
    $key_e4a8 = { b0 c0 [2] c4 d8 [2] 83 da [2] c4 cb [2] 8a c7 [2] 86 cd [2] 91 c6 [2] 8a 88 [2] b7 }

  condition:
    any of them
}