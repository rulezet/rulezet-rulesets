rule TTP_XOR_MULT_DOSStub_62bf {
  strings:
    $key_62bf = { 36 d7 [2] 42 cf [2] 05 cd [2] 42 dc [2] 0c d0 [2] 00 da [2] 17 d1 [2] 0c 9f [2] 31 }

  condition:
    any of them
}