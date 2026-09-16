rule TTP_XOR_MULT_DOSStub_3fd2 {
  strings:
    $key_3fd2 = { 6b ba [2] 1f a2 [2] 58 a0 [2] 1f b1 [2] 51 bd [2] 5d b7 [2] 4a bc [2] 51 f2 [2] 6c }

  condition:
    any of them
}