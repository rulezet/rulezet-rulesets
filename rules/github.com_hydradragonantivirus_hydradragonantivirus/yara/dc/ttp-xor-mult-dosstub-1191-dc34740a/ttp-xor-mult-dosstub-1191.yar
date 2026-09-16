rule TTP_XOR_MULT_DOSStub_1191 {
  strings:
    $key_1191 = { 45 f9 [2] 31 e1 [2] 76 e3 [2] 31 f2 [2] 7f fe [2] 73 f4 [2] 64 ff [2] 7f b1 [2] 42 }

  condition:
    any of them
}