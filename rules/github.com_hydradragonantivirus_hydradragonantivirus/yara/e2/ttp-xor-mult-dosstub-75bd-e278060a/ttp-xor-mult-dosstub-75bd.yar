rule TTP_XOR_MULT_DOSStub_75bd {
  strings:
    $key_75bd = { 21 d5 [2] 55 cd [2] 12 cf [2] 55 de [2] 1b d2 [2] 17 d8 [2] 00 d3 [2] 1b 9d [2] 26 }

  condition:
    any of them
}