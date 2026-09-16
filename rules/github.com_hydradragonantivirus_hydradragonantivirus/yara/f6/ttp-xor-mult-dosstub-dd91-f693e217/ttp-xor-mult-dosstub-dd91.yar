rule TTP_XOR_MULT_DOSStub_dd91 {
  strings:
    $key_dd91 = { 89 f9 [2] fd e1 [2] ba e3 [2] fd f2 [2] b3 fe [2] bf f4 [2] a8 ff [2] b3 b1 [2] 8e }

  condition:
    any of them
}