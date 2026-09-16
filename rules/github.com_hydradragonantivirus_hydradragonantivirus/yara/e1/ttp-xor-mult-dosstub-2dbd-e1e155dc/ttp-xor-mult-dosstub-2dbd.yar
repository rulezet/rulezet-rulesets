rule TTP_XOR_MULT_DOSStub_2dbd {
  strings:
    $key_2dbd = { 79 d5 [2] 0d cd [2] 4a cf [2] 0d de [2] 43 d2 [2] 4f d8 [2] 58 d3 [2] 43 9d [2] 7e }

  condition:
    any of them
}