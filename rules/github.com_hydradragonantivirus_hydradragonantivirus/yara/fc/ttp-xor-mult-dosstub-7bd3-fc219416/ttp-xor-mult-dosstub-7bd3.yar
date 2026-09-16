rule TTP_XOR_MULT_DOSStub_7bd3 {
  strings:
    $key_7bd3 = { 2f bb [2] 5b a3 [2] 1c a1 [2] 5b b0 [2] 15 bc [2] 19 b6 [2] 0e bd [2] 15 f3 [2] 28 }

  condition:
    any of them
}