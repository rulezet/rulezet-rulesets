rule TTP_XOR_MULT_DOSStub_e5a5 {
  strings:
    $key_e5a5 = { b1 cd [2] c5 d5 [2] 82 d7 [2] c5 c6 [2] 8b ca [2] 87 c0 [2] 90 cb [2] 8b 85 [2] b6 }

  condition:
    any of them
}