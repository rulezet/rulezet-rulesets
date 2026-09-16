rule TTP_XOR_MULT_DOSStub_ffc9 {
  strings:
    $key_ffc9 = { ab a1 [2] df b9 [2] 98 bb [2] df aa [2] 91 a6 [2] 9d ac [2] 8a a7 [2] 91 e9 [2] ac }

  condition:
    any of them
}