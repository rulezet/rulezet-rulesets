rule TTP_XOR_MULT_DOSStub_5224 {
  strings:
    $key_5224 = { 06 4c [2] 72 54 [2] 35 56 [2] 72 47 [2] 3c 4b [2] 30 41 [2] 27 4a [2] 3c 04 [2] 01 }

  condition:
    any of them
}