rule TTP_XOR_MULT_DOSStub_e2a8 {
  strings:
    $key_e2a8 = { b6 c0 [2] c2 d8 [2] 85 da [2] c2 cb [2] 8c c7 [2] 80 cd [2] 97 c6 [2] 8c 88 [2] b1 }

  condition:
    any of them
}