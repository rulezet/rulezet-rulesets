rule TTP_XOR_MULT_DOSStub_27d2 {
  strings:
    $key_27d2 = { 73 ba [2] 07 a2 [2] 40 a0 [2] 07 b1 [2] 49 bd [2] 45 b7 [2] 52 bc [2] 49 f2 [2] 74 }

  condition:
    any of them
}