rule TTP_XOR_MULT_DOSStub_05bf {
  strings:
    $key_05bf = { 51 d7 [2] 25 cf [2] 62 cd [2] 25 dc [2] 6b d0 [2] 67 da [2] 70 d1 [2] 6b 9f [2] 56 }

  condition:
    any of them
}