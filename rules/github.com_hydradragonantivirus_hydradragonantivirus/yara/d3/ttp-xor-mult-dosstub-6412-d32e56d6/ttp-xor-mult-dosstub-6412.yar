rule TTP_XOR_MULT_DOSStub_6412 {
  strings:
    $key_6412 = { 30 7a [2] 44 62 [2] 03 60 [2] 44 71 [2] 0a 7d [2] 06 77 [2] 11 7c [2] 0a 32 [2] 37 }

  condition:
    any of them
}