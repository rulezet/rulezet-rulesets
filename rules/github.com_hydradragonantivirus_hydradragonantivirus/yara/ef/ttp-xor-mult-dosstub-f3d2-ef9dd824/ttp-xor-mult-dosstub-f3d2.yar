rule TTP_XOR_MULT_DOSStub_f3d2 {
  strings:
    $key_f3d2 = { a7 ba [2] d3 a2 [2] 94 a0 [2] d3 b1 [2] 9d bd [2] 91 b7 [2] 86 bc [2] 9d f2 [2] a0 }

  condition:
    any of them
}