rule TTP_XOR_MULT_DOSStub_dfc3 {
  strings:
    $key_dfc3 = { 8b ab [2] ff b3 [2] b8 b1 [2] ff a0 [2] b1 ac [2] bd a6 [2] aa ad [2] b1 e3 [2] 8c }

  condition:
    any of them
}