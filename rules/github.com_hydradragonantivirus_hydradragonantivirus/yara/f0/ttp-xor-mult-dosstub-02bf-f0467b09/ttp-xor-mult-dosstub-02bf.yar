rule TTP_XOR_MULT_DOSStub_02bf {
  strings:
    $key_02bf = { 56 d7 [2] 22 cf [2] 65 cd [2] 22 dc [2] 6c d0 [2] 60 da [2] 77 d1 [2] 6c 9f [2] 51 }

  condition:
    any of them
}