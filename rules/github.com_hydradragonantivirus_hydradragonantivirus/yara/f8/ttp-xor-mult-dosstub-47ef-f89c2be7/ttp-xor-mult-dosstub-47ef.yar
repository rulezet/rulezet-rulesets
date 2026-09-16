rule TTP_XOR_MULT_DOSStub_47ef {
  strings:
    $key_47ef = { 13 87 [2] 67 9f [2] 20 9d [2] 67 8c [2] 29 80 [2] 25 8a [2] 32 81 [2] 29 cf [2] 14 }

  condition:
    any of them
}