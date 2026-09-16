rule TTP_XOR_MULT_DOSStub_3791 {
  strings:
    $key_3791 = { 63 f9 [2] 17 e1 [2] 50 e3 [2] 17 f2 [2] 59 fe [2] 55 f4 [2] 42 ff [2] 59 b1 [2] 64 }

  condition:
    any of them
}