rule TTP_XOR_MULT_DOSStub_bd9f {
  strings:
    $key_bd9f = { e9 f7 [2] 9d ef [2] da ed [2] 9d fc [2] d3 f0 [2] df fa [2] c8 f1 [2] d3 bf [2] ee }

  condition:
    any of them
}