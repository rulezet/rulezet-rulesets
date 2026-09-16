rule TTP_XOR_MULT_DOSStub_bdfa {
  strings:
    $key_bdfa = { e9 92 [2] 9d 8a [2] da 88 [2] 9d 99 [2] d3 95 [2] df 9f [2] c8 94 [2] d3 da [2] ee }

  condition:
    any of them
}