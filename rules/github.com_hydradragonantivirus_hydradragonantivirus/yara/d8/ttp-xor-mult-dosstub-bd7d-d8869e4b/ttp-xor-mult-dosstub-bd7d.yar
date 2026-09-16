rule TTP_XOR_MULT_DOSStub_bd7d {
  strings:
    $key_bd7d = { e9 15 [2] 9d 0d [2] da 0f [2] 9d 1e [2] d3 12 [2] df 18 [2] c8 13 [2] d3 5d [2] ee }

  condition:
    any of them
}