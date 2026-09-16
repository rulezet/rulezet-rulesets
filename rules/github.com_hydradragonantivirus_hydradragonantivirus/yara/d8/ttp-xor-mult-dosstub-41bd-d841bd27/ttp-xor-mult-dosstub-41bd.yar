rule TTP_XOR_MULT_DOSStub_41bd {
  strings:
    $key_41bd = { 15 d5 [2] 61 cd [2] 26 cf [2] 61 de [2] 2f d2 [2] 23 d8 [2] 34 d3 [2] 2f 9d [2] 12 }

  condition:
    any of them
}