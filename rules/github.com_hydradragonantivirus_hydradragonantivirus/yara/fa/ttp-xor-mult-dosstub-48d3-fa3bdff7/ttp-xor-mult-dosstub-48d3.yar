rule TTP_XOR_MULT_DOSStub_48d3 {
  strings:
    $key_48d3 = { 1c bb [2] 68 a3 [2] 2f a1 [2] 68 b0 [2] 26 bc [2] 2a b6 [2] 3d bd [2] 26 f3 [2] 1b }

  condition:
    any of them
}