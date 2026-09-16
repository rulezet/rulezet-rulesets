rule TTP_XOR_MULT_DOSStub_1624 {
  strings:
    $key_1624 = { 42 4c [2] 36 54 [2] 71 56 [2] 36 47 [2] 78 4b [2] 74 41 [2] 63 4a [2] 78 04 [2] 45 }

  condition:
    any of them
}