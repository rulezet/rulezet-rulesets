rule TTP_XOR_MULT_DOSStub_0dd3 {
  strings:
    $key_0dd3 = { 59 bb [2] 2d a3 [2] 6a a1 [2] 2d b0 [2] 63 bc [2] 6f b6 [2] 78 bd [2] 63 f3 [2] 5e }

  condition:
    any of them
}