rule TTP_XOR_MULT_DOSStub_75bf {
  strings:
    $key_75bf = { 21 d7 [2] 55 cf [2] 12 cd [2] 55 dc [2] 1b d0 [2] 17 da [2] 00 d1 [2] 1b 9f [2] 26 }

  condition:
    any of them
}