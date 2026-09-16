rule TTP_XOR_MULT_DOSStub_b6ef {
  strings:
    $key_b6ef = { e2 87 [2] 96 9f [2] d1 9d [2] 96 8c [2] d8 80 [2] d4 8a [2] c3 81 [2] d8 cf [2] e5 }

  condition:
    any of them
}