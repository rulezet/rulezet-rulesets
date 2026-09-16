rule TTP_XOR_MULT_DOSStub_a0bd {
  strings:
    $key_a0bd = { f4 d5 [2] 80 cd [2] c7 cf [2] 80 de [2] ce d2 [2] c2 d8 [2] d5 d3 [2] ce 9d [2] f3 }

  condition:
    any of them
}