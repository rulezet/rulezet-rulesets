rule TTP_XOR_MULT_DOSStub_bd86 {
  strings:
    $key_bd86 = { e9 ee [2] 9d f6 [2] da f4 [2] 9d e5 [2] d3 e9 [2] df e3 [2] c8 e8 [2] d3 a6 [2] ee }

  condition:
    any of them
}