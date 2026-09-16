rule TTP_XOR_MULT_DOSStub_76bd {
  strings:
    $key_76bd = { 22 d5 [2] 56 cd [2] 11 cf [2] 56 de [2] 18 d2 [2] 14 d8 [2] 03 d3 [2] 18 9d [2] 25 }

  condition:
    any of them
}