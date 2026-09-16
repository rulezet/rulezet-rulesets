rule TTP_XOR_MULT_DOSStub_18bd {
  strings:
    $key_18bd = { 4c d5 [2] 38 cd [2] 7f cf [2] 38 de [2] 76 d2 [2] 7a d8 [2] 6d d3 [2] 76 9d [2] 4b }

  condition:
    any of them
}