rule TTP_XOR_MULT_DOSStub_d6ef {
  strings:
    $key_d6ef = { 82 87 [2] f6 9f [2] b1 9d [2] f6 8c [2] b8 80 [2] b4 8a [2] a3 81 [2] b8 cf [2] 85 }

  condition:
    any of them
}