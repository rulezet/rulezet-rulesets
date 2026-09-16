rule TTP_XOR_MULT_DOSStub_4fdf {
  strings:
    $key_4fdf = { 1b b7 [2] 6f af [2] 28 ad [2] 6f bc [2] 21 b0 [2] 2d ba [2] 3a b1 [2] 21 ff [2] 1c }

  condition:
    any of them
}