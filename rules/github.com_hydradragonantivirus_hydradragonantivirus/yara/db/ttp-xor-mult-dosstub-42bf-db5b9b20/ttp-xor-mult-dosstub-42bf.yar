rule TTP_XOR_MULT_DOSStub_42bf {
  strings:
    $key_42bf = { 16 d7 [2] 62 cf [2] 25 cd [2] 62 dc [2] 2c d0 [2] 20 da [2] 37 d1 [2] 2c 9f [2] 11 }

  condition:
    any of them
}