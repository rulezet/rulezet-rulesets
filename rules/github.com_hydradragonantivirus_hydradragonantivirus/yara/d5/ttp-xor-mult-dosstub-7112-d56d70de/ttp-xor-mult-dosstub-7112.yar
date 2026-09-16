rule TTP_XOR_MULT_DOSStub_7112 {
  strings:
    $key_7112 = { 25 7a [2] 51 62 [2] 16 60 [2] 51 71 [2] 1f 7d [2] 13 77 [2] 04 7c [2] 1f 32 [2] 22 }

  condition:
    any of them
}