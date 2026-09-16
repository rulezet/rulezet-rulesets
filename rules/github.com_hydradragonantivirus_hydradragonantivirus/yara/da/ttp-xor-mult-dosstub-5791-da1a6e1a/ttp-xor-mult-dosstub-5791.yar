rule TTP_XOR_MULT_DOSStub_5791 {
  strings:
    $key_5791 = { 03 f9 [2] 77 e1 [2] 30 e3 [2] 77 f2 [2] 39 fe [2] 35 f4 [2] 22 ff [2] 39 b1 [2] 04 }

  condition:
    any of them
}