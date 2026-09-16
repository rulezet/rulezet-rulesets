rule TTP_XOR_MULT_DOSStub_01bd {
  strings:
    $key_01bd = { 55 d5 [2] 21 cd [2] 66 cf [2] 21 de [2] 6f d2 [2] 63 d8 [2] 74 d3 [2] 6f 9d [2] 52 }

  condition:
    any of them
}