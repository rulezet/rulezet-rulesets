rule TTP_XOR_MULT_DOSStub_6fc2 {
  strings:
    $key_6fc2 = { 3b aa [2] 4f b2 [2] 08 b0 [2] 4f a1 [2] 01 ad [2] 0d a7 [2] 1a ac [2] 01 e2 [2] 3c }

  condition:
    any of them
}