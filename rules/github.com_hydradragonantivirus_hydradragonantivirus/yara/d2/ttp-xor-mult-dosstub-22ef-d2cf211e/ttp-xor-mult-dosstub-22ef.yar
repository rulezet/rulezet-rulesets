rule TTP_XOR_MULT_DOSStub_22ef {
  strings:
    $key_22ef = { 76 87 [2] 02 9f [2] 45 9d [2] 02 8c [2] 4c 80 [2] 40 8a [2] 57 81 [2] 4c cf [2] 71 }

  condition:
    any of them
}