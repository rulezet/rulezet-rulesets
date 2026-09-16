rule TTP_XOR_MULT_DOSStub_7124 {
  strings:
    $key_7124 = { 25 4c [2] 51 54 [2] 16 56 [2] 51 47 [2] 1f 4b [2] 13 41 [2] 04 4a [2] 1f 04 [2] 22 }

  condition:
    any of them
}