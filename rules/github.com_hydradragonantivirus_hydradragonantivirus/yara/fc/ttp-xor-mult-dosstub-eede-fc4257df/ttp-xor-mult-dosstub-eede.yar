rule TTP_XOR_MULT_DOSStub_eede {
  strings:
    $key_eede = { ba b6 [2] ce ae [2] 89 ac [2] ce bd [2] 80 b1 [2] 8c bb [2] 9b b0 [2] 80 fe [2] bd }

  condition:
    any of them
}