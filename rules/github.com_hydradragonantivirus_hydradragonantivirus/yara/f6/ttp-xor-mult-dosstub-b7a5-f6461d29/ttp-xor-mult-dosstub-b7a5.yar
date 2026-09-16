rule TTP_XOR_MULT_DOSStub_b7a5 {
  strings:
    $key_b7a5 = { e3 cd [2] 97 d5 [2] d0 d7 [2] 97 c6 [2] d9 ca [2] d5 c0 [2] c2 cb [2] d9 85 [2] e4 }

  condition:
    any of them
}