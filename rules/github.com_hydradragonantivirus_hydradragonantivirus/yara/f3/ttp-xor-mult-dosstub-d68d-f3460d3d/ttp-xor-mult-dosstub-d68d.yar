rule TTP_XOR_MULT_DOSStub_d68d {
  strings:
    $key_d68d = { 82 e5 [2] f6 fd [2] b1 ff [2] f6 ee [2] b8 e2 [2] b4 e8 [2] a3 e3 [2] b8 ad [2] 85 }

  condition:
    any of them
}