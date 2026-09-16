rule TTP_XOR_MULT_DOSStub_13bd {
  strings:
    $key_13bd = { 47 d5 [2] 33 cd [2] 74 cf [2] 33 de [2] 7d d2 [2] 71 d8 [2] 66 d3 [2] 7d 9d [2] 40 }

  condition:
    any of them
}