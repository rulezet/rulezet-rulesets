rule TTP_XOR_MULT_DOSStub_04bd {
  strings:
    $key_04bd = { 50 d5 [2] 24 cd [2] 63 cf [2] 24 de [2] 6a d2 [2] 66 d8 [2] 71 d3 [2] 6a 9d [2] 57 }

  condition:
    any of them
}