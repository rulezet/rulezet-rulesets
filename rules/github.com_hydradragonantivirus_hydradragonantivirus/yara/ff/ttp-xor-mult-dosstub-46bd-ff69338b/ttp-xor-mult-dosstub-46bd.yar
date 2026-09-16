rule TTP_XOR_MULT_DOSStub_46bd {
  strings:
    $key_46bd = { 12 d5 [2] 66 cd [2] 21 cf [2] 66 de [2] 28 d2 [2] 24 d8 [2] 33 d3 [2] 28 9d [2] 15 }

  condition:
    any of them
}