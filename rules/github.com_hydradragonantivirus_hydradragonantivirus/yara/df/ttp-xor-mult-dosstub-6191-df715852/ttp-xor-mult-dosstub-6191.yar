rule TTP_XOR_MULT_DOSStub_6191 {
  strings:
    $key_6191 = { 35 f9 [2] 41 e1 [2] 06 e3 [2] 41 f2 [2] 0f fe [2] 03 f4 [2] 14 ff [2] 0f b1 [2] 32 }

  condition:
    any of them
}