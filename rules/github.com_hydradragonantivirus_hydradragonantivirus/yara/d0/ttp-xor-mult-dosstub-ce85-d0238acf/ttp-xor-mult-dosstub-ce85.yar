rule TTP_XOR_MULT_DOSStub_ce85 {
  strings:
    $key_ce85 = { 9a ed [2] ee f5 [2] a9 f7 [2] ee e6 [2] a0 ea [2] ac e0 [2] bb eb [2] a0 a5 [2] 9d }

  condition:
    any of them
}