rule TTP_XOR_MULT_DOSStub_53bd {
  strings:
    $key_53bd = { 07 d5 [2] 73 cd [2] 34 cf [2] 73 de [2] 3d d2 [2] 31 d8 [2] 26 d3 [2] 3d 9d [2] 00 }

  condition:
    any of them
}