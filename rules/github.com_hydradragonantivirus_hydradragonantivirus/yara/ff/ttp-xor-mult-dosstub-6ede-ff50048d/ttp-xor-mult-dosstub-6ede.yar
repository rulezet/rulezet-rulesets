rule TTP_XOR_MULT_DOSStub_6ede {
  strings:
    $key_6ede = { 3a b6 [2] 4e ae [2] 09 ac [2] 4e bd [2] 00 b1 [2] 0c bb [2] 1b b0 [2] 00 fe [2] 3d }

  condition:
    any of them
}