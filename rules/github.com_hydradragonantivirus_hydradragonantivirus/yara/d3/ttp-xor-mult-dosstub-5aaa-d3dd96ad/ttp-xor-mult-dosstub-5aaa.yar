rule TTP_XOR_MULT_DOSStub_5aaa {
  strings:
    $key_5aaa = { 0e c2 [2] 7a da [2] 3d d8 [2] 7a c9 [2] 34 c5 [2] 38 cf [2] 2f c4 [2] 34 8a [2] 09 }

  condition:
    any of them
}