rule TTP_XOR_MULT_DOSStub_91a5 {
  strings:
    $key_91a5 = { c5 cd [2] b1 d5 [2] f6 d7 [2] b1 c6 [2] ff ca [2] f3 c0 [2] e4 cb [2] ff 85 [2] c2 }

  condition:
    any of them
}