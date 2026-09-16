rule TTP_XOR_MULT_DOSStub_3112 {
  strings:
    $key_3112 = { 65 7a [2] 11 62 [2] 56 60 [2] 11 71 [2] 5f 7d [2] 53 77 [2] 44 7c [2] 5f 32 [2] 62 }

  condition:
    any of them
}