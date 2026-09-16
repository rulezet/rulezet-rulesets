rule TTP_XOR_MULT_DOSStub_0dc4 {
  strings:
    $key_0dc4 = { 59 ac [2] 2d b4 [2] 6a b6 [2] 2d a7 [2] 63 ab [2] 6f a1 [2] 78 aa [2] 63 e4 [2] 5e }

  condition:
    any of them
}