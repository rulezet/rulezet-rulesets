rule TTP_XOR_MULT_DOSStub_1325 {
  strings:
    $key_1325 = { 47 4d [2] 33 55 [2] 74 57 [2] 33 46 [2] 7d 4a [2] 71 40 [2] 66 4b [2] 7d 05 [2] 40 }

  condition:
    any of them
}