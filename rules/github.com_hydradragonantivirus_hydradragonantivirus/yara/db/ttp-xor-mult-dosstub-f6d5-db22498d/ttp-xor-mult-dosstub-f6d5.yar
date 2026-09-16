rule TTP_XOR_MULT_DOSStub_f6d5 {
  strings:
    $key_f6d5 = { a2 bd [2] d6 a5 [2] 91 a7 [2] d6 b6 [2] 98 ba [2] 94 b0 [2] 83 bb [2] 98 f5 [2] a5 }

  condition:
    any of them
}