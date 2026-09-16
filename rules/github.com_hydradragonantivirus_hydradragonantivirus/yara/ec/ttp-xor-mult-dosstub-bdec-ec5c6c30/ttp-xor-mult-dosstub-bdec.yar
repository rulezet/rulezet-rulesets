rule TTP_XOR_MULT_DOSStub_bdec {
  strings:
    $key_bdec = { e9 84 [2] 9d 9c [2] da 9e [2] 9d 8f [2] d3 83 [2] df 89 [2] c8 82 [2] d3 cc [2] ee }

  condition:
    any of them
}