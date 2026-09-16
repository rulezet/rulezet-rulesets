rule TTP_XOR_MULT_DOSStub_47bd {
  strings:
    $key_47bd = { 13 d5 [2] 67 cd [2] 20 cf [2] 67 de [2] 29 d2 [2] 25 d8 [2] 32 d3 [2] 29 9d [2] 14 }

  condition:
    any of them
}