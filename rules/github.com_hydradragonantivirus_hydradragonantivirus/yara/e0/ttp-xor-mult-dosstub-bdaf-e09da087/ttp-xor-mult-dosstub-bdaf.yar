rule TTP_XOR_MULT_DOSStub_bdaf {
  strings:
    $key_bdaf = { e9 c7 [2] 9d df [2] da dd [2] 9d cc [2] d3 c0 [2] df ca [2] c8 c1 [2] d3 8f [2] ee }

  condition:
    any of them
}