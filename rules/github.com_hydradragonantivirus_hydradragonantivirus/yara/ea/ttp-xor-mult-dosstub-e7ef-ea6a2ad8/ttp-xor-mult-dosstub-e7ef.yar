rule TTP_XOR_MULT_DOSStub_e7ef {
  strings:
    $key_e7ef = { b3 87 [2] c7 9f [2] 80 9d [2] c7 8c [2] 89 80 [2] 85 8a [2] 92 81 [2] 89 cf [2] b4 }

  condition:
    any of them
}