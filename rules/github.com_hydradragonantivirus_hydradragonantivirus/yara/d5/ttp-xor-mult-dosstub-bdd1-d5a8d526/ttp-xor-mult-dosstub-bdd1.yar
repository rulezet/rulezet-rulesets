rule TTP_XOR_MULT_DOSStub_bdd1 {
  strings:
    $key_bdd1 = { e9 b9 [2] 9d a1 [2] da a3 [2] 9d b2 [2] d3 be [2] df b4 [2] c8 bf [2] d3 f1 [2] ee }

  condition:
    any of them
}