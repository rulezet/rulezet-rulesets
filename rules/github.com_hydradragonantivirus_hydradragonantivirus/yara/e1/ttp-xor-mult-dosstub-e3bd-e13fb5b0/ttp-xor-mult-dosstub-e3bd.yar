rule TTP_XOR_MULT_DOSStub_e3bd {
  strings:
    $key_e3bd = { b7 d5 [2] c3 cd [2] 84 cf [2] c3 de [2] 8d d2 [2] 81 d8 [2] 96 d3 [2] 8d 9d [2] b0 }

  condition:
    any of them
}