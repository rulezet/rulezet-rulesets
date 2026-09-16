rule TTP_XOR_MULT_DOSStub_7fde {
  strings:
    $key_7fde = { 2b b6 [2] 5f ae [2] 18 ac [2] 5f bd [2] 11 b1 [2] 1d bb [2] 0a b0 [2] 11 fe [2] 2c }

  condition:
    any of them
}