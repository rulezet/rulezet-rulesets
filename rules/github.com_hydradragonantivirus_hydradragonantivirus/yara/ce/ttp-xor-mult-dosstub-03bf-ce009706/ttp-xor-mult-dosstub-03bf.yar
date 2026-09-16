rule TTP_XOR_MULT_DOSStub_03bf {
  strings:
    $key_03bf = { 57 d7 [2] 23 cf [2] 64 cd [2] 23 dc [2] 6d d0 [2] 61 da [2] 76 d1 [2] 6d 9f [2] 50 }

  condition:
    any of them
}