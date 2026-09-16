rule TTP_XOR_MULT_DOSStub_c2a5 {
  strings:
    $key_c2a5 = { 96 cd [2] e2 d5 [2] a5 d7 [2] e2 c6 [2] ac ca [2] a0 c0 [2] b7 cb [2] ac 85 [2] 91 }

  condition:
    any of them
}