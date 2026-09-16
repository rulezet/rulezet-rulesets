rule TTP_XOR_MULT_DOSStub_e9c9 {
  strings:
    $key_e9c9 = { bd a1 [2] c9 b9 [2] 8e bb [2] c9 aa [2] 87 a6 [2] 8b ac [2] 9c a7 [2] 87 e9 [2] ba }

  condition:
    any of them
}