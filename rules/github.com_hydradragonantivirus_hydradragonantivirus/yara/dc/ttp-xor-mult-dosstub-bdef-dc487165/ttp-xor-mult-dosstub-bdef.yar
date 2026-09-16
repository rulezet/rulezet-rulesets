rule TTP_XOR_MULT_DOSStub_bdef {
  strings:
    $key_bdef = { e9 87 [2] 9d 9f [2] da 9d [2] 9d 8c [2] d3 80 [2] df 8a [2] c8 81 [2] d3 cf [2] ee }

  condition:
    any of them
}