rule TTP_XOR_MULT_DOSStub_04ef {
  strings:
    $key_04ef = { 50 87 [2] 24 9f [2] 63 9d [2] 24 8c [2] 6a 80 [2] 66 8a [2] 71 81 [2] 6a cf [2] 57 }

  condition:
    any of them
}