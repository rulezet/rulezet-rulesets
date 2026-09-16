rule TTP_XOR_MULT_DOSStub_d49a {
  strings:
    $key_d49a = { 80 f2 [2] f4 ea [2] b3 e8 [2] f4 f9 [2] ba f5 [2] b6 ff [2] a1 f4 [2] ba ba [2] 87 }

  condition:
    any of them
}