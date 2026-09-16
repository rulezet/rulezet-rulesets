rule TTP_XOR_MULT_DOSStub_06c4 {
  strings:
    $key_06c4 = { 52 ac [2] 26 b4 [2] 61 b6 [2] 26 a7 [2] 68 ab [2] 64 a1 [2] 73 aa [2] 68 e4 [2] 55 }

  condition:
    any of them
}