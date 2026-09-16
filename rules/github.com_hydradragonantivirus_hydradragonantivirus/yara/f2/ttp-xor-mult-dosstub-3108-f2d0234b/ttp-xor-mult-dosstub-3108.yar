rule TTP_XOR_MULT_DOSStub_3108 {
  strings:
    $key_3108 = { 65 60 [2] 11 78 [2] 56 7a [2] 11 6b [2] 5f 67 [2] 53 6d [2] 44 66 [2] 5f 28 [2] 62 }

  condition:
    any of them
}