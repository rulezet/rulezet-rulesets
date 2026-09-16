rule TTP_XOR_MULT_DOSStub_bd4e {
  strings:
    $key_bd4e = { e9 26 [2] 9d 3e [2] da 3c [2] 9d 2d [2] d3 21 [2] df 2b [2] c8 20 [2] d3 6e [2] ee }

  condition:
    any of them
}