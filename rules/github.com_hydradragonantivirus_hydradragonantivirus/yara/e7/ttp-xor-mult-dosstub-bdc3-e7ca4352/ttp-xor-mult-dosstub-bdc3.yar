rule TTP_XOR_MULT_DOSStub_bdc3 {
  strings:
    $key_bdc3 = { e9 ab [2] 9d b3 [2] da b1 [2] 9d a0 [2] d3 ac [2] df a6 [2] c8 ad [2] d3 e3 [2] ee }

  condition:
    any of them
}