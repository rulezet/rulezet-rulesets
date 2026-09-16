rule TTP_XOR_MULT_DOSStub_bd49 {
  strings:
    $key_bd49 = { e9 21 [2] 9d 39 [2] da 3b [2] 9d 2a [2] d3 26 [2] df 2c [2] c8 27 [2] d3 69 [2] ee }

  condition:
    any of them
}