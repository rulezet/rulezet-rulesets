rule TTP_XOR_MULT_DOSStub_bdc6 {
  strings:
    $key_bdc6 = { e9 ae [2] 9d b6 [2] da b4 [2] 9d a5 [2] d3 a9 [2] df a3 [2] c8 a8 [2] d3 e6 [2] ee }

  condition:
    any of them
}