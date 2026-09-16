rule TTP_XOR_MULT_DOSStub_dfc4 {
  strings:
    $key_dfc4 = { 8b ac [2] ff b4 [2] b8 b6 [2] ff a7 [2] b1 ab [2] bd a1 [2] aa aa [2] b1 e4 [2] 8c }

  condition:
    any of them
}