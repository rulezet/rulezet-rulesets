rule TTP_XOR_MULT_DOSStub_40bf {
  strings:
    $key_40bf = { 14 d7 [2] 60 cf [2] 27 cd [2] 60 dc [2] 2e d0 [2] 22 da [2] 35 d1 [2] 2e 9f [2] 13 }

  condition:
    any of them
}