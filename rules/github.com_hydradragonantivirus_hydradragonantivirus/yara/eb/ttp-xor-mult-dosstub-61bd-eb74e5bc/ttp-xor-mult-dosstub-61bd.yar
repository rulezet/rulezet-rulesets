rule TTP_XOR_MULT_DOSStub_61bd {
  strings:
    $key_61bd = { 35 d5 [2] 41 cd [2] 06 cf [2] 41 de [2] 0f d2 [2] 03 d8 [2] 14 d3 [2] 0f 9d [2] 32 }

  condition:
    any of them
}