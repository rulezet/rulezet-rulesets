rule TTP_XOR_MULT_DOSStub_60bf {
  strings:
    $key_60bf = { 34 d7 [2] 40 cf [2] 07 cd [2] 40 dc [2] 0e d0 [2] 02 da [2] 15 d1 [2] 0e 9f [2] 33 }

  condition:
    any of them
}