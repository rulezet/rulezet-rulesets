rule TTP_XOR_MULT_DOSStub_f791 {
  strings:
    $key_f791 = { a3 f9 [2] d7 e1 [2] 90 e3 [2] d7 f2 [2] 99 fe [2] 95 f4 [2] 82 ff [2] 99 b1 [2] a4 }

  condition:
    any of them
}