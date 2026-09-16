rule TTP_XOR_MULT_DOSStub_f6d9 {
  strings:
    $key_f6d9 = { a2 b1 [2] d6 a9 [2] 91 ab [2] d6 ba [2] 98 b6 [2] 94 bc [2] 83 b7 [2] 98 f9 [2] a5 }

  condition:
    any of them
}