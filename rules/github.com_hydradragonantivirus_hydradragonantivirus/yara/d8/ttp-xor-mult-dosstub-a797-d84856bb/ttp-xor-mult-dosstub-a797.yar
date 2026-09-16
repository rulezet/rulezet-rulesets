rule TTP_XOR_MULT_DOSStub_a797 {
  strings:
    $key_a797 = { f3 ff [2] 87 e7 [2] c0 e5 [2] 87 f4 [2] c9 f8 [2] c5 f2 [2] d2 f9 [2] c9 b7 [2] f4 }

  condition:
    any of them
}