rule TTP_XOR_MULT_DOSStub_41ef {
  strings:
    $key_41ef = { 15 87 [2] 61 9f [2] 26 9d [2] 61 8c [2] 2f 80 [2] 23 8a [2] 34 81 [2] 2f cf [2] 12 }

  condition:
    any of them
}