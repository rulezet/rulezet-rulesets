rule TTP_XOR_MULT_DOSStub_4191 {
  strings:
    $key_4191 = { 15 f9 [2] 61 e1 [2] 26 e3 [2] 61 f2 [2] 2f fe [2] 23 f4 [2] 34 ff [2] 2f b1 [2] 12 }

  condition:
    any of them
}