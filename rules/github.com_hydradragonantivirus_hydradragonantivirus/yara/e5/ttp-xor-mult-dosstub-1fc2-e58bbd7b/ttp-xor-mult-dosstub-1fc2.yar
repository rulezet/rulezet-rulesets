rule TTP_XOR_MULT_DOSStub_1fc2 {
  strings:
    $key_1fc2 = { 4b aa [2] 3f b2 [2] 78 b0 [2] 3f a1 [2] 71 ad [2] 7d a7 [2] 6a ac [2] 71 e2 [2] 4c }

  condition:
    any of them
}