rule TTP_XOR_MULT_DOSStub_e1bf {
  strings:
    $key_e1bf = { b5 d7 [2] c1 cf [2] 86 cd [2] c1 dc [2] 8f d0 [2] 83 da [2] 94 d1 [2] 8f 9f [2] b2 }

  condition:
    any of them
}