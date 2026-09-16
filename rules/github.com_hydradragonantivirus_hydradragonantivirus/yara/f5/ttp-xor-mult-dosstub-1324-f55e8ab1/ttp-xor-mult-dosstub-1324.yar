rule TTP_XOR_MULT_DOSStub_1324 {
  strings:
    $key_1324 = { 47 4c [2] 33 54 [2] 74 56 [2] 33 47 [2] 7d 4b [2] 71 41 [2] 66 4a [2] 7d 04 [2] 40 }

  condition:
    any of them
}