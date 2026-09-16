rule TTP_XOR_MULT_DOSStub_2269 {
  strings:
    $key_2269 = { 76 01 [2] 02 19 [2] 45 1b [2] 02 0a [2] 4c 06 [2] 40 0c [2] 57 07 [2] 4c 49 [2] 71 }

  condition:
    any of them
}