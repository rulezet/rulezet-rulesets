rule TTP_XOR_MULT_DOSStub_5fde {
  strings:
    $key_5fde = { 0b b6 [2] 7f ae [2] 38 ac [2] 7f bd [2] 31 b1 [2] 3d bb [2] 2a b0 [2] 31 fe [2] 0c }

  condition:
    any of them
}