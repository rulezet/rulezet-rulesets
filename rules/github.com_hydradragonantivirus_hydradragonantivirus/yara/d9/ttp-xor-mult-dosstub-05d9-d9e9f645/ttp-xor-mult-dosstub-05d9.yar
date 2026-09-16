rule TTP_XOR_MULT_DOSStub_05d9 {
  strings:
    $key_05d9 = { 51 b1 [2] 25 a9 [2] 62 ab [2] 25 ba [2] 6b b6 [2] 67 bc [2] 70 b7 [2] 6b f9 [2] 56 }

  condition:
    any of them
}