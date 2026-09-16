rule TTP_XOR_MULT_DOSStub_25d2 {
  strings:
    $key_25d2 = { 71 ba [2] 05 a2 [2] 42 a0 [2] 05 b1 [2] 4b bd [2] 47 b7 [2] 50 bc [2] 4b f2 [2] 76 }

  condition:
    any of them
}