rule TTP_XOR_MULT_DOSStub_1ede {
  strings:
    $key_1ede = { 4a b6 [2] 3e ae [2] 79 ac [2] 3e bd [2] 70 b1 [2] 7c bb [2] 6b b0 [2] 70 fe [2] 4d }

  condition:
    any of them
}