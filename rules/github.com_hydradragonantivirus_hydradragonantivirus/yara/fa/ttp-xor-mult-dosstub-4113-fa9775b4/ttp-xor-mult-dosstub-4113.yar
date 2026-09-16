rule TTP_XOR_MULT_DOSStub_4113 {
  strings:
    $key_4113 = { 15 7b [2] 61 63 [2] 26 61 [2] 61 70 [2] 2f 7c [2] 23 76 [2] 34 7d [2] 2f 33 [2] 12 }

  condition:
    any of them
}