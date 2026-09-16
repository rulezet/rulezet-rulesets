rule TTP_XOR_MULT_DOSStub_2ec4 {
  strings:
    $key_2ec4 = { 7a ac [2] 0e b4 [2] 49 b6 [2] 0e a7 [2] 40 ab [2] 4c a1 [2] 5b aa [2] 40 e4 [2] 7d }

  condition:
    any of them
}