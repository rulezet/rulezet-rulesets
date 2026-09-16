rule TTP_XOR_MULT_DOSStub_c2a8 {
  strings:
    $key_c2a8 = { 96 c0 [2] e2 d8 [2] a5 da [2] e2 cb [2] ac c7 [2] a0 cd [2] b7 c6 [2] ac 88 [2] 91 }

  condition:
    any of them
}