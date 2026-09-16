rule TTP_XOR_MULT_DOSStub_4fc2 {
  strings:
    $key_4fc2 = { 1b aa [2] 6f b2 [2] 28 b0 [2] 6f a1 [2] 21 ad [2] 2d a7 [2] 3a ac [2] 21 e2 [2] 1c }

  condition:
    any of them
}