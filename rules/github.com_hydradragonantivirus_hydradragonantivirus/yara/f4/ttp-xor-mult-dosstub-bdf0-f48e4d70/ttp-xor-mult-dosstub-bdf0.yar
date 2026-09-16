rule TTP_XOR_MULT_DOSStub_bdf0 {
  strings:
    $key_bdf0 = { e9 98 [2] 9d 80 [2] da 82 [2] 9d 93 [2] d3 9f [2] df 95 [2] c8 9e [2] d3 d0 [2] ee }

  condition:
    any of them
}