rule TTP_XOR_MULT_DOSStub_f191 {
  strings:
    $key_f191 = { a5 f9 [2] d1 e1 [2] 96 e3 [2] d1 f2 [2] 9f fe [2] 93 f4 [2] 84 ff [2] 9f b1 [2] a2 }

  condition:
    any of them
}