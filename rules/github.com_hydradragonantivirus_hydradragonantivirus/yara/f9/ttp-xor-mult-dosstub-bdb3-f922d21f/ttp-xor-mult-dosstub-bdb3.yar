rule TTP_XOR_MULT_DOSStub_bdb3 {
  strings:
    $key_bdb3 = { e9 db [2] 9d c3 [2] da c1 [2] 9d d0 [2] d3 dc [2] df d6 [2] c8 dd [2] d3 93 [2] ee }

  condition:
    any of them
}