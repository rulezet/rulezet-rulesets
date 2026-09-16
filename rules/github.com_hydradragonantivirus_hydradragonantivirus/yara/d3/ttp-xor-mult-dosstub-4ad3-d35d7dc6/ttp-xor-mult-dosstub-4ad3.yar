rule TTP_XOR_MULT_DOSStub_4ad3 {
  strings:
    $key_4ad3 = { 1e bb [2] 6a a3 [2] 2d a1 [2] 6a b0 [2] 24 bc [2] 28 b6 [2] 3f bd [2] 24 f3 [2] 19 }

  condition:
    any of them
}