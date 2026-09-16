rule TTP_XOR_MULT_DOSStub_5024 {
  strings:
    $key_5024 = { 04 4c [2] 70 54 [2] 37 56 [2] 70 47 [2] 3e 4b [2] 32 41 [2] 25 4a [2] 3e 04 [2] 03 }

  condition:
    any of them
}