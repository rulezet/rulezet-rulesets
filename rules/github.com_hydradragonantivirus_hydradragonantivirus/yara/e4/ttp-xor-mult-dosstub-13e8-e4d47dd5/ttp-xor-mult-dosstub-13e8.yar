rule TTP_XOR_MULT_DOSStub_13e8 {
  strings:
    $key_13e8 = { 47 80 [2] 33 98 [2] 74 9a [2] 33 8b [2] 7d 87 [2] 71 8d [2] 66 86 [2] 7d c8 [2] 40 }

  condition:
    any of them
}