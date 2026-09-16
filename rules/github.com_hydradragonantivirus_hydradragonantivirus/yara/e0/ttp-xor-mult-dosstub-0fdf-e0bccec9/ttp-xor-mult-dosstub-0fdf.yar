rule TTP_XOR_MULT_DOSStub_0fdf {
  strings:
    $key_0fdf = { 5b b7 [2] 2f af [2] 68 ad [2] 2f bc [2] 61 b0 [2] 6d ba [2] 7a b1 [2] 61 ff [2] 5c }

  condition:
    any of them
}