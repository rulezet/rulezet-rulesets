rule TTP_XOR_MULT_DOSStub_1808 {
  strings:
    $key_1808 = { 4c 60 [2] 38 78 [2] 7f 7a [2] 38 6b [2] 76 67 [2] 7a 6d [2] 6d 66 [2] 76 28 [2] 4b }

  condition:
    any of them
}