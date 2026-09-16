rule TTP_XOR_MULT_DOSStub_e091 {
  strings:
    $key_e091 = { b4 f9 [2] c0 e1 [2] 87 e3 [2] c0 f2 [2] 8e fe [2] 82 f4 [2] 95 ff [2] 8e b1 [2] b3 }

  condition:
    any of them
}