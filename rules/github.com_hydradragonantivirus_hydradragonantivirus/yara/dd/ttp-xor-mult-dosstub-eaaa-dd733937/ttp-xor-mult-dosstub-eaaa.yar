rule TTP_XOR_MULT_DOSStub_eaaa {
  strings:
    $key_eaaa = { be c2 [2] ca da [2] 8d d8 [2] ca c9 [2] 84 c5 [2] 88 cf [2] 9f c4 [2] 84 8a [2] b9 }

  condition:
    any of them
}