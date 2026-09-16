rule TTP_XOR_MULT_DOSStub_69bd {
  strings:
    $key_69bd = { 3d d5 [2] 49 cd [2] 0e cf [2] 49 de [2] 07 d2 [2] 0b d8 [2] 1c d3 [2] 07 9d [2] 3a }

  condition:
    any of them
}