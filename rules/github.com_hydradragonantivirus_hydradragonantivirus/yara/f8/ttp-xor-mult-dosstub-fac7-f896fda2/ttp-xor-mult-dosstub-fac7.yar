rule TTP_XOR_MULT_DOSStub_fac7 {
  strings:
    $key_fac7 = { ae af [2] da b7 [2] 9d b5 [2] da a4 [2] 94 a8 [2] 98 a2 [2] 8f a9 [2] 94 e7 [2] a9 }

  condition:
    any of them
}