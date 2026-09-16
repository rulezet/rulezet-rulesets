rule TTP_XOR_MULT_DOSStub_bd87 {
  strings:
    $key_bd87 = { e9 ef [2] 9d f7 [2] da f5 [2] 9d e4 [2] d3 e8 [2] df e2 [2] c8 e9 [2] d3 a7 [2] ee }

  condition:
    any of them
}