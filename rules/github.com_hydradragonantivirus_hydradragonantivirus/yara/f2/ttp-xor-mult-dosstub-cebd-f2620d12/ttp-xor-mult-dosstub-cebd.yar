rule TTP_XOR_MULT_DOSStub_cebd {
  strings:
    $key_cebd = { 9a d5 [2] ee cd [2] a9 cf [2] ee de [2] a0 d2 [2] ac d8 [2] bb d3 [2] a0 9d [2] 9d }

  condition:
    any of them
}