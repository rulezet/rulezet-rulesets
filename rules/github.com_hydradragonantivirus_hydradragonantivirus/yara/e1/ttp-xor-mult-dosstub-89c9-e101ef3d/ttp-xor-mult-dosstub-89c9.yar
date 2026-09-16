rule TTP_XOR_MULT_DOSStub_89c9 {
  strings:
    $key_89c9 = { dd a1 [2] a9 b9 [2] ee bb [2] a9 aa [2] e7 a6 [2] eb ac [2] fc a7 [2] e7 e9 [2] da }

  condition:
    any of them
}