rule TTP_XOR_MULT_DOSStub_bd2c {
  strings:
    $key_bd2c = { e9 44 [2] 9d 5c [2] da 5e [2] 9d 4f [2] d3 43 [2] df 49 [2] c8 42 [2] d3 0c [2] ee }

  condition:
    any of them
}