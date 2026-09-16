rule TTP_XOR_MULT_DOSStub_c084 {
  strings:
    $key_c084 = { 94 ec [2] e0 f4 [2] a7 f6 [2] e0 e7 [2] ae eb [2] a2 e1 [2] b5 ea [2] ae a4 [2] 93 }

  condition:
    any of them
}