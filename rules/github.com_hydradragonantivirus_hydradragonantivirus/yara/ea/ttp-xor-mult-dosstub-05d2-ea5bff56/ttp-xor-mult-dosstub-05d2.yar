rule TTP_XOR_MULT_DOSStub_05d2 {
  strings:
    $key_05d2 = { 51 ba [2] 25 a2 [2] 62 a0 [2] 25 b1 [2] 6b bd [2] 67 b7 [2] 70 bc [2] 6b f2 [2] 56 }

  condition:
    any of them
}