rule TTP_XOR_MULT_DOSStub_bdd7 {
  strings:
    $key_bdd7 = { e9 bf [2] 9d a7 [2] da a5 [2] 9d b4 [2] d3 b8 [2] df b2 [2] c8 b9 [2] d3 f7 [2] ee }

  condition:
    any of them
}