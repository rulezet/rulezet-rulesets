rule TTP_XOR_MULT_DOSStub_c8c9 {
  strings:
    $key_c8c9 = { 9c a1 [2] e8 b9 [2] af bb [2] e8 aa [2] a6 a6 [2] aa ac [2] bd a7 [2] a6 e9 [2] 9b }

  condition:
    any of them
}