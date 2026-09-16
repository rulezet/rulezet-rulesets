rule TTP_XOR_MULT_DOSStub_cdde {
  strings:
    $key_cdde = { 99 b6 [2] ed ae [2] aa ac [2] ed bd [2] a3 b1 [2] af bb [2] b8 b0 [2] a3 fe [2] 9e }

  condition:
    any of them
}