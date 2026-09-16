rule TTP_XOR_MULT_DOSStub_15bd {
  strings:
    $key_15bd = { 41 d5 [2] 35 cd [2] 72 cf [2] 35 de [2] 7b d2 [2] 77 d8 [2] 60 d3 [2] 7b 9d [2] 46 }

  condition:
    any of them
}