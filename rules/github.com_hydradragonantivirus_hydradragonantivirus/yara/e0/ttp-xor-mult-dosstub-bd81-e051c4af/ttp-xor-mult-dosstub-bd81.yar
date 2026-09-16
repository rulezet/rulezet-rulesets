rule TTP_XOR_MULT_DOSStub_bd81 {
  strings:
    $key_bd81 = { e9 e9 [2] 9d f1 [2] da f3 [2] 9d e2 [2] d3 ee [2] df e4 [2] c8 ef [2] d3 a1 [2] ee }

  condition:
    any of them
}