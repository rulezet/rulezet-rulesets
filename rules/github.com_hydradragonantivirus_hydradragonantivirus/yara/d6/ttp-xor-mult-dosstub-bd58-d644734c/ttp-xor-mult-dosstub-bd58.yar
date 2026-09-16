rule TTP_XOR_MULT_DOSStub_bd58 {
  strings:
    $key_bd58 = { e9 30 [2] 9d 28 [2] da 2a [2] 9d 3b [2] d3 37 [2] df 3d [2] c8 36 [2] d3 78 [2] ee }

  condition:
    any of them
}