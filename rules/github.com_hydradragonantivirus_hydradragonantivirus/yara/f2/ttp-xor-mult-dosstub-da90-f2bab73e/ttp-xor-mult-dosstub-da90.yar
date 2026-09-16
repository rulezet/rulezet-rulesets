rule TTP_XOR_MULT_DOSStub_da90 {
  strings:
    $key_da90 = { 8e f8 [2] fa e0 [2] bd e2 [2] fa f3 [2] b4 ff [2] b8 f5 [2] af fe [2] b4 b0 [2] 89 }

  condition:
    any of them
}