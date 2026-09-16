rule TTP_XOR_MULT_DOSStub_e0a8 {
  strings:
    $key_e0a8 = { b4 c0 [2] c0 d8 [2] 87 da [2] c0 cb [2] 8e c7 [2] 82 cd [2] 95 c6 [2] 8e 88 [2] b3 }

  condition:
    any of them
}