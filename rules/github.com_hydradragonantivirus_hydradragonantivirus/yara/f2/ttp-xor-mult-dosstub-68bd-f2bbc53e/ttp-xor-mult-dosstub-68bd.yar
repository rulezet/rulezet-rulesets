rule TTP_XOR_MULT_DOSStub_68bd {
  strings:
    $key_68bd = { 3c d5 [2] 48 cd [2] 0f cf [2] 48 de [2] 06 d2 [2] 0a d8 [2] 1d d3 [2] 06 9d [2] 3b }

  condition:
    any of them
}