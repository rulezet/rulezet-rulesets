rule TTP_XOR_MULT_DOSStub_bd88 {
  strings:
    $key_bd88 = { e9 e0 [2] 9d f8 [2] da fa [2] 9d eb [2] d3 e7 [2] df ed [2] c8 e6 [2] d3 a8 [2] ee }

  condition:
    any of them
}