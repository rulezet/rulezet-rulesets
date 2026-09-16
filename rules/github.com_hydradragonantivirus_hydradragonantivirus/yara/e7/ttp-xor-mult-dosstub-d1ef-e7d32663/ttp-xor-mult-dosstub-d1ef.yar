rule TTP_XOR_MULT_DOSStub_d1ef {
  strings:
    $key_d1ef = { 85 87 [2] f1 9f [2] b6 9d [2] f1 8c [2] bf 80 [2] b3 8a [2] a4 81 [2] bf cf [2] 82 }

  condition:
    any of them
}