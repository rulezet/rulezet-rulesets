rule TTP_XOR_MULT_DOSStub_faaa {
  strings:
    $key_faaa = { ae c2 [2] da da [2] 9d d8 [2] da c9 [2] 94 c5 [2] 98 cf [2] 8f c4 [2] 94 8a [2] a9 }

  condition:
    any of them
}