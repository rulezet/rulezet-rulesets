rule TTP_XOR_MULT_DOSStub_e5bd {
  strings:
    $key_e5bd = { b1 d5 [2] c5 cd [2] 82 cf [2] c5 de [2] 8b d2 [2] 87 d8 [2] 90 d3 [2] 8b 9d [2] b6 }

  condition:
    any of them
}