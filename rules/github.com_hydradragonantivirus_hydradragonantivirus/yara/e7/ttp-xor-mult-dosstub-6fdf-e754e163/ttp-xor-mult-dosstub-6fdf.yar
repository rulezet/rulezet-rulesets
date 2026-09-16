rule TTP_XOR_MULT_DOSStub_6fdf {
  strings:
    $key_6fdf = { 3b b7 [2] 4f af [2] 08 ad [2] 4f bc [2] 01 b0 [2] 0d ba [2] 1a b1 [2] 01 ff [2] 3c }

  condition:
    any of them
}