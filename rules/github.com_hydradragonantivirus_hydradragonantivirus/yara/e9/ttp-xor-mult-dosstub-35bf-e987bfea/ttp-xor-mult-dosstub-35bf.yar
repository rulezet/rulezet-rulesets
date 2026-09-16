rule TTP_XOR_MULT_DOSStub_35bf {
  strings:
    $key_35bf = { 61 d7 [2] 15 cf [2] 52 cd [2] 15 dc [2] 5b d0 [2] 57 da [2] 40 d1 [2] 5b 9f [2] 66 }

  condition:
    any of them
}