rule TTP_XOR_MULT_DOSStub_7fdf {
  strings:
    $key_7fdf = { 2b b7 [2] 5f af [2] 18 ad [2] 5f bc [2] 11 b0 [2] 1d ba [2] 0a b1 [2] 11 ff [2] 2c }

  condition:
    any of them
}