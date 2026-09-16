rule TTP_XOR_MULT_DOSStub_3124 {
  strings:
    $key_3124 = { 65 4c [2] 11 54 [2] 56 56 [2] 11 47 [2] 5f 4b [2] 53 41 [2] 44 4a [2] 5f 04 [2] 62 }

  condition:
    any of them
}