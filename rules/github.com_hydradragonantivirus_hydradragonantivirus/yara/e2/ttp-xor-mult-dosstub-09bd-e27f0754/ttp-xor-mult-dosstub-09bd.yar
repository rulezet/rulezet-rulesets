rule TTP_XOR_MULT_DOSStub_09bd {
  strings:
    $key_09bd = { 5d d5 [2] 29 cd [2] 6e cf [2] 29 de [2] 67 d2 [2] 6b d8 [2] 7c d3 [2] 67 9d [2] 5a }

  condition:
    any of them
}