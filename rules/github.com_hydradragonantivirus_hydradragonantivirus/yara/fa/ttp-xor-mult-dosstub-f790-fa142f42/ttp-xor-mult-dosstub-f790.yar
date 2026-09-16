rule TTP_XOR_MULT_DOSStub_f790 {
  strings:
    $key_f790 = { a3 f8 [2] d7 e0 [2] 90 e2 [2] d7 f3 [2] 99 ff [2] 95 f5 [2] 82 fe [2] 99 b0 [2] a4 }

  condition:
    any of them
}