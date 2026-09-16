rule TTP_XOR_MULT_DOSStub_1622 {
  strings:
    $key_1622 = { 42 4a [2] 36 52 [2] 71 50 [2] 36 41 [2] 78 4d [2] 74 47 [2] 63 4c [2] 78 02 [2] 45 }

  condition:
    any of them
}