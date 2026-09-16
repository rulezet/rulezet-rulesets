rule TTP_XOR_MULT_DOSStub_1fdf {
  strings:
    $key_1fdf = { 4b b7 [2] 3f af [2] 78 ad [2] 3f bc [2] 71 b0 [2] 7d ba [2] 6a b1 [2] 71 ff [2] 4c }

  condition:
    any of them
}