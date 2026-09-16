rule TTP_XOR_MULT_DOSStub_36bf {
  strings:
    $key_36bf = { 62 d7 [2] 16 cf [2] 51 cd [2] 16 dc [2] 58 d0 [2] 54 da [2] 43 d1 [2] 58 9f [2] 65 }

  condition:
    any of them
}