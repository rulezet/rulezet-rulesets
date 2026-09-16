rule TTP_XOR_MULT_DOSStub_77bd {
  strings:
    $key_77bd = { 23 d5 [2] 57 cd [2] 10 cf [2] 57 de [2] 19 d2 [2] 15 d8 [2] 02 d3 [2] 19 9d [2] 24 }

  condition:
    any of them
}