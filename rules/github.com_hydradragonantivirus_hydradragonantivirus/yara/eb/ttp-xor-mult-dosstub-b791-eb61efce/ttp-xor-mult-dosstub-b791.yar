rule TTP_XOR_MULT_DOSStub_b791 {
  strings:
    $key_b791 = { e3 f9 [2] 97 e1 [2] d0 e3 [2] 97 f2 [2] d9 fe [2] d5 f4 [2] c2 ff [2] d9 b1 [2] e4 }

  condition:
    any of them
}