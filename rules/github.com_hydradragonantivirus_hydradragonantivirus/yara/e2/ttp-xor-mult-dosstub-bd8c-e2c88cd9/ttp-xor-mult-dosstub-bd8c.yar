rule TTP_XOR_MULT_DOSStub_bd8c {
  strings:
    $key_bd8c = { e9 e4 [2] 9d fc [2] da fe [2] 9d ef [2] d3 e3 [2] df e9 [2] c8 e2 [2] d3 ac [2] ee }

  condition:
    any of them
}