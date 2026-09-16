rule TTP_XOR_MULT_DOSStub_d68a {
  strings:
    $key_d68a = { 82 e2 [2] f6 fa [2] b1 f8 [2] f6 e9 [2] b8 e5 [2] b4 ef [2] a3 e4 [2] b8 aa [2] 85 }

  condition:
    any of them
}