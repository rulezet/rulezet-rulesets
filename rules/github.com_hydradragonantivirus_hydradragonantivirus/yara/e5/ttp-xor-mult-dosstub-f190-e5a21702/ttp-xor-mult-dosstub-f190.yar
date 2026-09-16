rule TTP_XOR_MULT_DOSStub_f190 {
  strings:
    $key_f190 = { a5 f8 [2] d1 e0 [2] 96 e2 [2] d1 f3 [2] 9f ff [2] 93 f5 [2] 84 fe [2] 9f b0 [2] a2 }

  condition:
    any of them
}