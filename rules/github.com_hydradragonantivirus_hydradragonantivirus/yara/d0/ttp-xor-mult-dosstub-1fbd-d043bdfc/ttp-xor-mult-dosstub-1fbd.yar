rule TTP_XOR_MULT_DOSStub_1fbd {
  strings:
    $key_1fbd = { 4b d5 [2] 3f cd [2] 78 cf [2] 3f de [2] 71 d2 [2] 7d d8 [2] 6a d3 [2] 71 9d [2] 4c }

  condition:
    any of them
}