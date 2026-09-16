rule TTP_XOR_MULT_DOSStub_ecdf {
  strings:
    $key_ecdf = { b8 b7 [2] cc af [2] 8b ad [2] cc bc [2] 82 b0 [2] 8e ba [2] 99 b1 [2] 82 ff [2] bf }

  condition:
    any of them
}