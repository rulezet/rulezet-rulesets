rule TTP_XOR_MULT_DOSStub_da8c {
  strings:
    $key_da8c = { 8e e4 [2] fa fc [2] bd fe [2] fa ef [2] b4 e3 [2] b8 e9 [2] af e2 [2] b4 ac [2] 89 }

  condition:
    any of them
}