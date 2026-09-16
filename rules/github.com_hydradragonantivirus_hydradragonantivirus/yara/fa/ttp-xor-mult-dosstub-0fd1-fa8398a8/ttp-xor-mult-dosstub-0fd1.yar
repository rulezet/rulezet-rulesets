rule TTP_XOR_MULT_DOSStub_0fd1 {
  strings:
    $key_0fd1 = { 5b b9 [2] 2f a1 [2] 68 a3 [2] 2f b2 [2] 61 be [2] 6d b4 [2] 7a bf [2] 61 f1 [2] 5c }

  condition:
    any of them
}