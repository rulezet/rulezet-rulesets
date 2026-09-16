rule TTP_XOR_MULT_DOSStub_b3a5 {
  strings:
    $key_b3a5 = { e7 cd [2] 93 d5 [2] d4 d7 [2] 93 c6 [2] dd ca [2] d1 c0 [2] c6 cb [2] dd 85 [2] e0 }

  condition:
    any of them
}