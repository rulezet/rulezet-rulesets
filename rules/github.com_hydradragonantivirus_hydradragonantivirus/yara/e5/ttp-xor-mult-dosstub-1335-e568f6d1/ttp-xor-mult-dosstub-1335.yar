rule TTP_XOR_MULT_DOSStub_1335 {
  strings:
    $key_1335 = { 47 5d [2] 33 45 [2] 74 47 [2] 33 56 [2] 7d 5a [2] 71 50 [2] 66 5b [2] 7d 15 [2] 40 }

  condition:
    any of them
}