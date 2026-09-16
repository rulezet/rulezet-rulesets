rule TTP_XOR_MULT_DOSStub_16f2 {
  strings:
    $key_16f2 = { 42 9a [2] 36 82 [2] 71 80 [2] 36 91 [2] 78 9d [2] 74 97 [2] 63 9c [2] 78 d2 [2] 45 }

  condition:
    any of them
}