rule TTP_XOR_MULT_DOSStub_b2bd {
  strings:
    $key_b2bd = { e6 d5 [2] 92 cd [2] d5 cf [2] 92 de [2] dc d2 [2] d0 d8 [2] c7 d3 [2] dc 9d [2] e1 }

  condition:
    any of them
}