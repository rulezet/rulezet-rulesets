rule TTP_XOR_MULT_DOSStub_51bf {
  strings:
    $key_51bf = { 05 d7 [2] 71 cf [2] 36 cd [2] 71 dc [2] 3f d0 [2] 33 da [2] 24 d1 [2] 3f 9f [2] 02 }

  condition:
    any of them
}