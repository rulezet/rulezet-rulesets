rule TTP_XOR_MULT_DOSStub_bd6d {
  strings:
    $key_bd6d = { e9 05 [2] 9d 1d [2] da 1f [2] 9d 0e [2] d3 02 [2] df 08 [2] c8 03 [2] d3 4d [2] ee }

  condition:
    any of them
}